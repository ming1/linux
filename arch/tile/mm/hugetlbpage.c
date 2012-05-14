/*
 * Copyright 2010 Tilera Corporation. All Rights Reserved.
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation, version 2.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 *   NON INFRINGEMENT.  See the GNU General Public License for
 *   more details.
 *
 * TILE Huge TLB Page Support for Kernel.
 * Taken from i386 hugetlb implementation:
 * Copyright (C) 2002, Rohit Seth <rohit.seth@intel.com>
 */

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/sysctl.h>
#include <linux/mman.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/setup.h>

#ifdef CONFIG_HUGETLB_SUPER_PAGES
/* "Extra" page-size multipliers, one per level of the page table. */
int huge_shift[HUGE_SHIFT_ENTRIES];

/*
 * This routine is a hybrid of pte_alloc_map() and pte_alloc_kernel().
 * It assumes that L2 PTEs are never in HIGHMEM (we don't support that).
 * It locks the user pagetable, and bumps up the mm->nr_ptes field,
 * but otherwise allocate the page table using the kernel versions.
 */
static pte_t *pte_alloc_hugetlb(struct mm_struct *mm, pmd_t *pmd,
				unsigned long address)
{
	pte_t *new;

	if (pmd_none(*pmd)) {
		new = pte_alloc_one_kernel(mm, address);
		if (!new)
			return NULL;

		smp_wmb(); /* See comment in __pte_alloc */

		spin_lock(&mm->page_table_lock);
		if (likely(pmd_none(*pmd))) {  /* Has another populated it ? */
			mm->nr_ptes++;
			pmd_populate_kernel(mm, pmd, new);
			new = NULL;
		} else
			VM_BUG_ON(pmd_trans_splitting(*pmd));
		spin_unlock(&mm->page_table_lock);
		if (new)
			pte_free_kernel(mm, new);
	}

	return pte_offset_kernel(pmd, address);
}
#endif

pte_t *huge_pte_alloc(struct mm_struct *mm,
		      unsigned long addr, unsigned long sz)
{
	pgd_t *pgd;
	pud_t *pud;

	addr &= -sz;   /* Mask off any low bits in the address. */

	pgd = pgd_offset(mm, addr);
	pud = pud_alloc(mm, pgd, addr);

#ifdef CONFIG_HUGETLB_SUPER_PAGES
	if (sz >= PGDIR_SIZE) {
		BUG_ON(sz != PGDIR_SIZE &&
		       sz != PGDIR_SIZE << huge_shift[HUGE_SHIFT_PGDIR]);
		return (pte_t *)pud;
	} else {
		pmd_t *pmd = pmd_alloc(mm, pud, addr);
		if (sz >= PMD_SIZE) {
			BUG_ON(sz != PMD_SIZE &&
			       sz != (PMD_SIZE << huge_shift[HUGE_SHIFT_PMD]));
			return (pte_t *)pmd;
		}
		else {
			if (sz != PAGE_SIZE << huge_shift[HUGE_SHIFT_PAGE])
				panic("Unexpected page size %#lx\n", sz);
			return pte_alloc_hugetlb(mm, pmd, addr);
		}
	}
#else
	BUG_ON(sz != PMD_SIZE);
	return (pte_t *) pmd_alloc(mm, pud, addr);
#endif
}

static pte_t *get_pte(pte_t *base, int index, int level)
{
	pte_t *ptep = base + index;
#ifdef CONFIG_HUGETLB_SUPER_PAGES
	if (!pte_present(*ptep) && huge_shift[level] != 0) {
		unsigned long mask = -1UL << huge_shift[level];
		pte_t *super_ptep = base + (index & mask);
		pte_t pte = *super_ptep;
		if (pte_present(pte) && pte_super(pte))
			ptep = super_ptep;
	}
#endif
	return ptep;
}

pte_t *huge_pte_offset(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
#ifdef CONFIG_HUGETLB_SUPER_PAGES
	pte_t *pte;
#endif

	/* Get the top-level page table entry. */
	pgd = (pgd_t *)get_pte((pte_t *)mm->pgd, pgd_index(addr), 0);
	if (!pgd_present(*pgd))
		return NULL;

	/* We don't have four levels. */
	pud = pud_offset(pgd, addr);
#ifndef __PAGETABLE_PUD_FOLDED
# error support fourth page table level
#endif

	/* Check for an L0 huge PTE, if we have three levels. */
#ifndef __PAGETABLE_PMD_FOLDED
	if (pud_huge(*pud))
		return (pte_t *)pud;

	pmd = (pmd_t *)get_pte((pte_t *)pud_page_vaddr(*pud),
			       pmd_index(addr), 1);
	if (!pmd_present(*pmd))
		return NULL;
#else
	pmd = pmd_offset(pud, addr);
#endif

	/* Check for an L1 huge PTE. */
	if (pmd_huge(*pmd))
		return (pte_t *)pmd;

#ifdef CONFIG_HUGETLB_SUPER_PAGES
	/* Check for an L2 huge PTE. */
	pte = get_pte((pte_t *)pmd_page_vaddr(*pmd), pte_index(addr), 2);
	if (!pte_present(*pte))
		return NULL;
	if (pte_super(*pte))
		return pte;
#endif

	return NULL;
}

struct page *follow_huge_addr(struct mm_struct *mm, unsigned long address,
			      int write)
{
	return ERR_PTR(-EINVAL);
}

int pmd_huge(pmd_t pmd)
{
	return !!(pmd_val(pmd) & _PAGE_HUGE_PAGE);
}

int pud_huge(pud_t pud)
{
	return !!(pud_val(pud) & _PAGE_HUGE_PAGE);
}

struct page *follow_huge_pmd(struct mm_struct *mm, unsigned long address,
			     pmd_t *pmd, int write)
{
	struct page *page;

	page = pte_page(*(pte_t *)pmd);
	if (page)
		page += ((address & ~PMD_MASK) >> PAGE_SHIFT);
	return page;
}

struct page *follow_huge_pud(struct mm_struct *mm, unsigned long address,
			     pud_t *pud, int write)
{
	struct page *page;

	page = pte_page(*(pte_t *)pud);
	if (page)
		page += ((address & ~PUD_MASK) >> PAGE_SHIFT);
	return page;
}

int huge_pmd_unshare(struct mm_struct *mm, unsigned long *addr, pte_t *ptep)
{
	return 0;
}

#ifdef HAVE_ARCH_HUGETLB_UNMAPPED_AREA
static unsigned long hugetlb_get_unmapped_area_bottomup(struct file *file,
		unsigned long addr, unsigned long len,
		unsigned long pgoff, unsigned long flags)
{
	struct hstate *h = hstate_file(file);
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long start_addr;

	if (len > mm->cached_hole_size) {
		start_addr = mm->free_area_cache;
	} else {
		start_addr = TASK_UNMAPPED_BASE;
		mm->cached_hole_size = 0;
	}

full_search:
	addr = ALIGN(start_addr, huge_page_size(h));

	for (vma = find_vma(mm, addr); ; vma = vma->vm_next) {
		/* At this point:  (!vma || addr < vma->vm_end). */
		if (TASK_SIZE - len < addr) {
			/*
			 * Start a new search - just in case we missed
			 * some holes.
			 */
			if (start_addr != TASK_UNMAPPED_BASE) {
				start_addr = TASK_UNMAPPED_BASE;
				mm->cached_hole_size = 0;
				goto full_search;
			}
			return -ENOMEM;
		}
		if (!vma || addr + len <= vma->vm_start) {
			mm->free_area_cache = addr + len;
			return addr;
		}
		if (addr + mm->cached_hole_size < vma->vm_start)
			mm->cached_hole_size = vma->vm_start - addr;
		addr = ALIGN(vma->vm_end, huge_page_size(h));
	}
}

static unsigned long hugetlb_get_unmapped_area_topdown(struct file *file,
		unsigned long addr0, unsigned long len,
		unsigned long pgoff, unsigned long flags)
{
	struct hstate *h = hstate_file(file);
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma, *prev_vma;
	unsigned long base = mm->mmap_base, addr = addr0;
	unsigned long largest_hole = mm->cached_hole_size;
	int first_time = 1;

	/* don't allow allocations above current base */
	if (mm->free_area_cache > base)
		mm->free_area_cache = base;

	if (len <= largest_hole) {
		largest_hole = 0;
		mm->free_area_cache  = base;
	}
try_again:
	/* make sure it can fit in the remaining address space */
	if (mm->free_area_cache < len)
		goto fail;

	/* either no address requested or can't fit in requested address hole */
	addr = (mm->free_area_cache - len) & huge_page_mask(h);
	do {
		/*
		 * Lookup failure means no vma is above this address,
		 * i.e. return with success:
		 */
		vma = find_vma_prev(mm, addr, &prev_vma);
		if (!vma) {
			return addr;
			break;
		}

		/*
		 * new region fits between prev_vma->vm_end and
		 * vma->vm_start, use it:
		 */
		if (addr + len <= vma->vm_start &&
			    (!prev_vma || (addr >= prev_vma->vm_end))) {
			/* remember the address as a hint for next time */
			mm->cached_hole_size = largest_hole;
			mm->free_area_cache = addr;
			return addr;
		} else {
			/* pull free_area_cache down to the first hole */
			if (mm->free_area_cache == vma->vm_end) {
				mm->free_area_cache = vma->vm_start;
				mm->cached_hole_size = largest_hole;
			}
		}

		/* remember the largest hole we saw so far */
		if (addr + largest_hole < vma->vm_start)
			largest_hole = vma->vm_start - addr;

		/* try just below the current vma->vm_start */
		addr = (vma->vm_start - len) & huge_page_mask(h);

	} while (len <= vma->vm_start);

fail:
	/*
	 * if hint left us with no space for the requested
	 * mapping then try again:
	 */
	if (first_time) {
		mm->free_area_cache = base;
		largest_hole = 0;
		first_time = 0;
		goto try_again;
	}
	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */
	mm->free_area_cache = TASK_UNMAPPED_BASE;
	mm->cached_hole_size = ~0UL;
	addr = hugetlb_get_unmapped_area_bottomup(file, addr0,
			len, pgoff, flags);

	/*
	 * Restore the topdown base:
	 */
	mm->free_area_cache = base;
	mm->cached_hole_size = ~0UL;

	return addr;
}

unsigned long hugetlb_get_unmapped_area(struct file *file, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct hstate *h = hstate_file(file);
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;

	if (len & ~huge_page_mask(h))
		return -EINVAL;
	if (len > TASK_SIZE)
		return -ENOMEM;

	if (flags & MAP_FIXED) {
		if (prepare_hugepage_range(file, addr, len))
			return -EINVAL;
		return addr;
	}

	if (addr) {
		addr = ALIGN(addr, huge_page_size(h));
		vma = find_vma(mm, addr);
		if (TASK_SIZE - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;
	}
	if (current->mm->get_unmapped_area == arch_get_unmapped_area)
		return hugetlb_get_unmapped_area_bottomup(file, addr, len,
				pgoff, flags);
	else
		return hugetlb_get_unmapped_area_topdown(file, addr, len,
				pgoff, flags);
}

#ifdef CONFIG_HUGETLB_SUPER_PAGES
static void add_super_size(unsigned long ps, int level, int base_shift)
{
	int log_ps = __builtin_ctzl(ps);
	if ((1UL << log_ps) != ps || (log_ps & 1) != 0) {
		pr_warn("Not enabling %ld byte huge pages;"
			" must be a power of four.\n", ps);
		return;
	}
	if (log_ps != base_shift) {
		if (huge_shift[level] != 0) {
			int old_shift = base_shift + huge_shift[level];
			pr_warn("Not enabling %ld MB huge pages;"
				" already have size %ld MB.\n",
				ps >> 20, (1UL << old_shift) >> 20);
			return;
		}
		if (hv_set_pte_super_shift(level, log_ps - base_shift) != 0) {
			pr_warn("Not enabling %ld MB huge pages;"
				" no hypervisor support.\n", ps >> 20);
			return;
		}
		printk(KERN_DEBUG "Enabled %ld MB huge pages\n", ps >> 20);
		huge_shift[level] = log_ps - base_shift;
	}
	hugetlb_add_hstate(log_ps - PAGE_SHIFT);
}

static __init int __setup_hugepagesz(unsigned long ps)
{
	if (ps > 64*1024*1024*1024UL) {
		pr_warn("Not enabling %ld MB huge pages;"
			" largest legal value is 64 GB .\n", ps >> 20);
	}
	else if (ps >= PUD_SIZE) {
		static long hv_jpage_size;
		if (hv_jpage_size == 0)
			hv_jpage_size = hv_sysconf(HV_SYSCONF_PAGE_SIZE_JUMBO);
		if (hv_jpage_size != PUD_SIZE) {
			pr_warn("Not enabling >= %ld MB huge pages:"
				" hypervisor reports size %ld\n",
				PUD_SIZE >> 20, hv_jpage_size);
		}
		add_super_size(ps, 0, PUD_SHIFT);
	} else if (ps >= PMD_SIZE) {
		add_super_size(ps, 1, PMD_SHIFT);
	} else if (ps > PAGE_SIZE) {
		add_super_size(ps, 2, PAGE_SHIFT);
	} else {
		pr_err("hugepagesz: Unsupported page size %ld\n", ps);
	}
	return 1;
}

bool saw_hugepagesz;

static __init int setup_hugepagesz(char *opt)
{
	saw_hugepagesz = true;
	return __setup_hugepagesz(memparse(opt, NULL));
}
__setup("hugepagesz=", setup_hugepagesz);

/* Provide 1MB size as a standard default if nothing specified. */
static __init int add_default_hugepagesz(void)
{
	if (!saw_hugepagesz)
		__setup_hugepagesz(1 * 1024 * 1024UL);
	return 1;
}
arch_initcall(add_default_hugepagesz);
#endif

#endif /*HAVE_ARCH_HUGETLB_UNMAPPED_AREA*/

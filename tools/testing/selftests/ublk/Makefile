# SPDX-License-Identifier: GPL-2.0

include ../../../build/Build.include
include ../../../scripts/Makefile.arch
include ../../../scripts/Makefile.include

CFLAGS += -O3 -Wl,-no-as-needed -Wall -I $(top_srcdir)/usr/include
ifneq ($(WERROR),0)
	CFLAGS += -Werror
endif

LDLIBS += -lpthread -lm -luring

TEST_PROGS := test_generic_02.sh
TEST_PROGS += test_generic_03.sh
TEST_PROGS += test_generic_06.sh
TEST_PROGS += test_generic_07.sh

TEST_PROGS += test_generic_08.sh
TEST_PROGS += test_generic_09.sh
TEST_PROGS += test_generic_10.sh
TEST_PROGS += test_generic_12.sh
TEST_PROGS += test_generic_13.sh
TEST_PROGS += test_generic_16.sh

TEST_PROGS += test_batch_01.sh
TEST_PROGS += test_batch_02.sh
TEST_PROGS += test_batch_03.sh

TEST_PROGS += test_null_01.sh
TEST_PROGS += test_null_02.sh
TEST_PROGS += test_null_03.sh
TEST_PROGS += test_loop_01.sh
TEST_PROGS += test_loop_02.sh
TEST_PROGS += test_loop_03.sh
TEST_PROGS += test_loop_04.sh
TEST_PROGS += test_loop_05.sh
TEST_PROGS += test_loop_06.sh
TEST_PROGS += test_loop_07.sh

TEST_PROGS += test_integrity_01.sh
TEST_PROGS += test_integrity_02.sh

TEST_PROGS += test_recover_01.sh
TEST_PROGS += test_recover_02.sh
TEST_PROGS += test_recover_03.sh
TEST_PROGS += test_recover_04.sh
TEST_PROGS += test_stripe_01.sh
TEST_PROGS += test_stripe_02.sh
TEST_PROGS += test_stripe_03.sh
TEST_PROGS += test_stripe_04.sh
TEST_PROGS += test_stripe_05.sh
TEST_PROGS += test_stripe_06.sh

TEST_PROGS += test_part_01.sh
TEST_PROGS += test_part_02.sh

TEST_PROGS += test_stress_01.sh
TEST_PROGS += test_stress_02.sh
TEST_PROGS += test_stress_03.sh
TEST_PROGS += test_stress_04.sh
TEST_PROGS += test_stress_05.sh
TEST_PROGS += test_stress_06.sh
TEST_PROGS += test_stress_07.sh
TEST_PROGS += test_stress_08.sh
TEST_PROGS += test_stress_09.sh

TEST_PROGS += test_bpf_01.sh
TEST_PROGS += test_bpf_02.sh

TEST_FILES := settings

TEST_GEN_PROGS_EXTENDED = kublk metadata_size
STANDALONE_UTILS := metadata_size.c

LOCAL_HDRS += $(wildcard *.h)

OVERRIDE_TARGETS := 1
include ../lib.mk

###############
# BPF support #
###############

REPOROOT := $(abspath ../../../..)
TOOLSDIR := $(REPOROOT)/tools
LIBDIR := $(TOOLSDIR)/lib
BPFDIR := $(LIBDIR)/bpf
TOOLSINCDIR := $(TOOLSDIR)/include
BPFTOOLDIR := $(TOOLSDIR)/bpf/bpftool
APIDIR := $(TOOLSINCDIR)/uapi

BUILD_DIR := $(OUTPUT)/build
OBJ_DIR := $(BUILD_DIR)/obj
INCLUDE_DIR := $(BUILD_DIR)/include
BPFOBJ_DIR := $(OBJ_DIR)/libbpf
BPFOBJ := $(BPFOBJ_DIR)/libbpf.a
HOST_OBJ_DIR := $(OBJ_DIR)/host/bpftool
HOST_LIBBPF_OUTPUT := $(OBJ_DIR)/host/libbpf/
HOST_LIBBPF_DESTDIR := $(BUILD_DIR)/host/
HOST_DESTDIR := $(BUILD_DIR)/host/
DEFAULT_BPFTOOL := $(BUILD_DIR)/host/sbin/bpftool
BPFTOOL ?= $(DEFAULT_BPFTOOL)

# Prefer module BTF (/sys/kernel/btf/ublk_drv) so BPF struct_ops types
# are available even when CONFIG_BLK_DEV_UBLK=m. The module must be
# loaded when building the selftests for vmlinux.h generation.
VMLINUX_BTF_PATHS ?= /sys/kernel/btf/ublk_drv				\
		     $(if $(O),$(O)/vmlinux)				\
		     $(if $(KBUILD_OUTPUT),$(KBUILD_OUTPUT)/vmlinux)	\
		     ../../../../vmlinux				\
		     /sys/kernel/btf/vmlinux				\
		     /boot/vmlinux-$(shell uname -r)
VMLINUX_BTF ?= $(abspath $(firstword $(wildcard $(VMLINUX_BTF_PATHS))))

CLANG ?= clang

IS_LITTLE_ENDIAN = $(shell $(CC) -dM -E - </dev/null |			\
			grep 'define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__')

define get_sys_includes
$(shell $(1) $(2) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')
endef

ifneq ($(CROSS_COMPILE),)
CLANG_TARGET_ARCH = --target=$(notdir $(CROSS_COMPILE:%-=%))
endif

CLANG_SYS_INCLUDES = $(call get_sys_includes,$(CLANG),$(CLANG_TARGET_ARCH))

BPF_CFLAGS = -g -D__TARGET_ARCH_$(SRCARCH)				\
	     $(if $(IS_LITTLE_ENDIAN),-mlittle-endian,-mbig-endian)	\
	     -I$(INCLUDE_DIR) -I$(APIDIR)				\
	     -I$(REPOROOT)/include					\
	     $(CLANG_SYS_INCLUDES)					\
	     -Wall -Wno-compare-distinct-pointer-types			\
	     -O2 -mcpu=v3

MAKE_DIRS := $(sort $(OBJ_DIR)/libbpf $(BPFOBJ_DIR)			\
	       $(OBJ_DIR)/bpftool $(HOST_OBJ_DIR) $(INCLUDE_DIR)	\
	       $(OBJ_DIR)/ublk)

$(MAKE_DIRS):
	$(call msg,MKDIR,,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(BPFOBJ): $(wildcard $(BPFDIR)/*.[ch] $(BPFDIR)/Makefile)		\
	   $(APIDIR)/linux/bpf.h					\
	   | $(BPFOBJ_DIR)
	$(Q)$(MAKE) $(submake_extras) -C $(BPFDIR) OUTPUT=$(BPFOBJ_DIR)/\
		    ARCH=$(ARCH) CC="$(CC)" CROSS_COMPILE=$(CROSS_COMPILE)\
		    EXTRA_CFLAGS='-g -O0 -fPIC'				\
		    DESTDIR=$(BUILD_DIR) prefix= all install_headers

# Build bpftool
$(DEFAULT_BPFTOOL): $(wildcard $(BPFTOOLDIR)/*.[ch] $(BPFTOOLDIR)/Makefile) \
		    | $(HOST_OBJ_DIR)
	$(Q)$(MAKE) $(submake_extras) -C $(BPFTOOLDIR)			\
		    ARCH= CROSS_COMPILE= CC=$(HOSTCC) LD=$(HOSTLD)	\
		    EXTRA_CFLAGS='-g -O0'				\
		    OUTPUT=$(HOST_OBJ_DIR)/				\
		    LIBBPF_OUTPUT=$(HOST_LIBBPF_OUTPUT)			\
		    LIBBPF_DESTDIR=$(HOST_LIBBPF_DESTDIR)		\
		    prefix= DESTDIR=$(HOST_DESTDIR) install-bin

# Generate vmlinux.h
$(INCLUDE_DIR)/vmlinux.h: $(VMLINUX_BTF) $(BPFTOOL) | $(INCLUDE_DIR)
ifeq ($(VMLINUX_H),)
	$(call msg,GEN,,$@)
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@
else
	$(call msg,CP,,$@)
	$(Q)cp "$(VMLINUX_H)" $@
endif

# Compile BPF programs
$(OBJ_DIR)/ublk/%.bpf.o: bpf/%.bpf.c $(INCLUDE_DIR)/vmlinux.h | $(BPFOBJ) $(OBJ_DIR)/ublk
	$(call msg,CLNG-BPF,,$(notdir $@))
	$(Q)$(CLANG) $(BPF_CFLAGS) -target bpf -c $< -o $@

# Generate BPF skeletons
$(INCLUDE_DIR)/%.bpf.skel.h: $(OBJ_DIR)/ublk/%.bpf.o $(BPFTOOL) | $(INCLUDE_DIR)
	$(call msg,GEN-SKEL,,$(notdir $@))
	$(Q)$(BPFTOOL) gen object $(<:.o=.linked1.o) $<
	$(Q)$(BPFTOOL) gen object $(<:.o=.linked2.o) $(<:.o=.linked1.o)
	$(Q)$(BPFTOOL) gen object $(<:.o=.linked3.o) $(<:.o=.linked2.o)
	$(Q)$(BPFTOOL) gen skeleton $(<:.o=.linked3.o) name $(subst .bpf.skel.h,,$(notdir $@)) > $@

BPF_SKELS := $(INCLUDE_DIR)/ublk_null.bpf.skel.h \
	     $(INCLUDE_DIR)/ublk_dma_zc.bpf.skel.h

# kublk with BPF support
CFLAGS += -DHAVE_BPF -I$(INCLUDE_DIR) -I$(BUILD_DIR)/include
LDLIBS += -lelf -lz

$(OUTPUT)/kublk: $(filter-out $(STANDALONE_UTILS),$(wildcard *.c)) $(BPF_SKELS) $(BPFOBJ)
	$(CC) $(CFLAGS) $(filter %.c,$^) $(BPFOBJ) -o $@ $(LDFLAGS) $(LDLIBS)

$(OUTPUT)/metadata_size: metadata_size.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

override define CLEAN
	rm -rf $(BUILD_DIR)
	rm -f $(TEST_GEN_PROGS_EXTENDED)
endef

check:
	shellcheck -x -f gcc *.sh

# Test groups for running subsets of tests
# JOBS=1 (default): sequential with kselftest TAP output
# JOBS>1: parallel execution with xargs -P
# Usage: make run_null JOBS=4
JOBS ?= 1
export JOBS

# Auto-detect test groups from TEST_PROGS (test_<group>_<num>.sh -> group)
TEST_GROUPS := $(shell echo "$(TEST_PROGS)" | tr ' ' '\n' | \
	sed 's/test_\([^_]*\)_.*/\1/' | sort -u)

# Template for group test targets
# $(1) = group name (e.g., null, generic, stress)
define RUN_GROUP
run_$(1): all
	@if [ $$(JOBS) -gt 1 ]; then \
		echo $$(filter test_$(1)_%.sh,$$(TEST_PROGS)) | tr ' ' '\n' | \
			xargs -P $$(JOBS) -n1 sh -c './"$$$$0"' || true; \
	else \
		$$(call RUN_TESTS, $$(filter test_$(1)_%.sh,$$(TEST_PROGS))); \
	fi
.PHONY: run_$(1)
endef

# Generate targets for each discovered test group
$(foreach group,$(TEST_GROUPS),$(eval $(call RUN_GROUP,$(group))))

# Run all tests (parallel when JOBS>1)
run_all: all
	@if [ $(JOBS) -gt 1 ]; then \
		echo $(TEST_PROGS) | tr ' ' '\n' | \
			xargs -P $(JOBS) -n1 sh -c './"$$0"' || true; \
	else \
		$(call RUN_TESTS, $(TEST_PROGS)); \
	fi
.PHONY: run_all

.DEFAULT_GOAL := all
.DELETE_ON_ERROR:

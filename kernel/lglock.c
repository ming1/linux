/* See include/linux/lglock.h for description */
#include <linux/module.h>
#include <linux/lglock.h>
#include <linux/cpu.h>
#include <linux/string.h>

/* Note there is no uninit, so lglocks cannot be defined in
 * modules (but it's fine to use them from there)
 * Could be added though, just undo lg_lock_init
 */

void lg_lock_init(struct lglock *lg, char *name)
{
	int i;

	LOCKDEP_INIT_MAP(&lg->lock_dep_map, name, &lg->lock_key, 0);

	register_hotcpu_notifier(&lg->cpu_notifier);
	get_online_cpus();
	for_each_online_cpu (i)
		cpu_set(i, lg->cpus);
	put_online_cpus();
}
EXPORT_SYMBOL(lg_lock_init);

void lg_local_lock(struct lglock *lg)
{
	arch_spinlock_t *lock;
	preempt_disable();
	rwlock_acquire_read(&lg->lock_dep_map, 0, 0, _RET_IP_);
	lock = this_cpu_ptr(lg->lock);
	arch_spin_lock(lock);
}
EXPORT_SYMBOL(lg_local_lock);

void lg_local_unlock(struct lglock *lg)
{
	arch_spinlock_t *lock;
	rwlock_release(&lg->lock_dep_map, 1, _RET_IP_);
	lock = this_cpu_ptr(lg->lock);
	arch_spin_unlock(lock);
	preempt_enable();
}
EXPORT_SYMBOL(lg_local_unlock);

void lg_local_lock_cpu(struct lglock *lg, int cpu)
{
	arch_spinlock_t *lock;
	preempt_disable();
	rwlock_acquire_read(&lg->lock_dep_map, 0, 0, _RET_IP_);
	lock = per_cpu_ptr(lg->lock, cpu);
	arch_spin_lock(lock);
}
EXPORT_SYMBOL(lg_local_lock_cpu);

void lg_local_unlock_cpu(struct lglock *lg, int cpu)
{
	arch_spinlock_t *lock;
	rwlock_release(&lg->lock_dep_map, 1, _RET_IP_);
	lock = per_cpu_ptr(lg->lock, cpu);
	arch_spin_unlock(lock);
	preempt_enable();
}
EXPORT_SYMBOL(lg_local_unlock_cpu);

void lg_global_lock_online(struct lglock *lg)
{
	int i;
	spin_lock(&lg->cpu_lock);
	rwlock_acquire(&lg->lock_dep_map, 0, 0, _RET_IP_);
	for_each_cpu(i, &lg->cpus) {
		arch_spinlock_t *lock;
		lock = per_cpu_ptr(lg->lock, i);
		arch_spin_lock(lock);
	}
}
EXPORT_SYMBOL(lg_global_lock_online);

void lg_global_unlock_online(struct lglock *lg)
{
	int i;
	rwlock_release(&lg->lock_dep_map, 1, _RET_IP_);
	for_each_cpu(i, &lg->cpus) {
		arch_spinlock_t *lock;
		lock = per_cpu_ptr(lg->lock, i);
		arch_spin_unlock(lock);
	}
	spin_unlock(&lg->cpu_lock);
}
EXPORT_SYMBOL(lg_global_unlock_online);

void lg_global_lock(struct lglock *lg)
{
	int i;
	preempt_disable();
	rwlock_acquire(&lg->lock_dep_map, 0, 0, _RET_IP_);
	for_each_possible_cpu(i) {
		arch_spinlock_t *lock;
		lock = per_cpu_ptr(lg->lock, i);
		arch_spin_lock(lock);
	}
}
EXPORT_SYMBOL(lg_global_lock);

void lg_global_unlock(struct lglock *lg)
{
	int i;
	rwlock_release(&lg->lock_dep_map, 1, _RET_IP_);
	for_each_possible_cpu(i) {
		arch_spinlock_t *lock;
		lock = per_cpu_ptr(lg->lock, i);
		arch_spin_unlock(lock);
	}
	preempt_enable();
}
EXPORT_SYMBOL(lg_global_unlock);

int lg_cpu_callback(struct notifier_block *nb,
                              unsigned long action, void *hcpu)
{
	struct lglock *lglock = container_of(nb, struct lglock, cpu_notifier);
	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_UP_PREPARE:
		spin_lock(&lglock->cpu_lock);
		cpu_set((unsigned long)hcpu, lglock->cpus);
		spin_unlock(&lglock->cpu_lock);
		break;
	case CPU_UP_CANCELED: case CPU_DEAD:
		spin_lock(&lglock->cpu_lock);
		cpu_clear((unsigned long)hcpu, lglock->cpus);
		spin_unlock(&lglock->cpu_lock);
	}
	return NOTIFY_OK;
}
EXPORT_SYMBOL(lg_cpu_callback);


#ifndef __ASM_ARM_CPUIDLE_H
#define __ASM_ARM_CPUIDLE_H

#ifdef CONFIG_CPU_IDLE
extern int arm_cpuidle_simple_enter(struct cpuidle_device *dev,
		struct cpuidle_driver *drv, int index);
#else
static inline int arm_cpuidle_simple_enter(struct cpuidle_device *dev,
		struct cpuidle_driver *drv, int index) { return -ENODEV; }
#endif

/* Common ARM WFI state */
#define ARM_CPUIDLE_WFI_STATE {\
	.enter                  = arm_cpuidle_simple_enter,\
	.exit_latency           = 1,\
	.target_residency       = 1,\
	.flags                  = CPUIDLE_FLAG_TIME_VALID,\
	.name                   = "WFI",\
	.desc                   = "ARM WFI",\
}

#endif

zreladdr-$(CONFIG_ARCH_TEGRA_2x_SOC)	+= 0x00008000
params_phys-$(CONFIG_ARCH_TEGRA_2x_SOC)	:= 0x00000100
initrd_phys-$(CONFIG_ARCH_TEGRA_2x_SOC)	:= 0x00800000

dtb-$(CONFIG_ARCH_TEGRA_2x_SOC) += tegra-harmony.dtb
dtb-$(CONFIG_ARCH_TEGRA_2x_SOC) += tegra-paz00.dtb
dtb-$(CONFIG_ARCH_TEGRA_2x_SOC) += tegra-seaboard.dtb
dtb-$(CONFIG_ARCH_TEGRA_2x_SOC) += tegra-trimslice.dtb
dtb-$(CONFIG_ARCH_TEGRA_2x_SOC) += tegra-ventana.dtb
dtb-$(CONFIG_ARCH_TEGRA_2x_SOC) += tegra-whistler.dtb
dtb-$(CONFIG_ARCH_TEGRA_3x_SOC) += tegra-cardhu.dtb

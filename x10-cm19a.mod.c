#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x6b80720f, "module_layout" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0x15692c87, "param_ops_int" },
	{ 0x75de205b, "dev_set_drvdata" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x7fc4fd21, "malloc_sizes" },
	{ 0xc47bff11, "usb_kill_urb" },
	{ 0x358aaa4e, "usb_deregister_dev" },
	{ 0xfff68d14, "mutex_unlock" },
	{ 0x57dc8415, "nonseekable_open" },
	{ 0x7d11c268, "jiffies" },
	{ 0x68dfc59f, "__init_waitqueue_head" },
	{ 0x3b917721, "current_task" },
	{ 0xa693e359, "usb_deregister" },
	{ 0x188632eb, "mutex_lock_interruptible" },
	{ 0xc3ec5b7, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0x2da418b5, "copy_to_user" },
	{ 0x79d4f79a, "usb_register_dev" },
	{ 0x16305289, "warn_slowpath_null" },
	{ 0x6ef4214d, "mutex_lock" },
	{ 0x26dd208a, "usb_free_coherent" },
	{ 0xd563a872, "usb_submit_urb" },
	{ 0x8ff4079b, "pv_irq_ops" },
	{ 0x1e6b19a5, "usb_get_dev" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x9c7eea82, "usb_put_dev" },
	{ 0x4292364c, "schedule" },
	{ 0xd62c833f, "schedule_timeout" },
	{ 0xf1faac3a, "_raw_spin_lock_irq" },
	{ 0xae1b411d, "usb_find_interface" },
	{ 0xfddb17e7, "kmem_cache_alloc_trace" },
	{ 0x67f7403e, "_raw_spin_lock" },
	{ 0xe45f60d8, "__wake_up" },
	{ 0x37a0cba, "kfree" },
	{ 0x622fa02a, "prepare_to_wait" },
	{ 0xcd898e65, "usb_register_driver" },
	{ 0x75bb675a, "finish_wait" },
	{ 0xb81960ca, "snprintf" },
	{ 0x8235805b, "memmove" },
	{ 0x666a7790, "usb_alloc_coherent" },
	{ 0x33d169c9, "_copy_from_user" },
	{ 0xaa68bf39, "dev_get_drvdata" },
	{ 0x63bd62ad, "usb_free_urb" },
	{ 0xfdd5bafa, "usb_alloc_urb" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=usbcore";

MODULE_ALIAS("usb:v0BC7p0002d*dc*dsc*dp*ic*isc*ip*in*");

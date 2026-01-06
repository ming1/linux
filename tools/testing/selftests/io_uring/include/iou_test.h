/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Red Hat, Inc.
 */

#ifndef __IOU_TEST_H__
#define __IOU_TEST_H__

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

enum iou_test_status {
	IOU_TEST_PASS = 0,
	IOU_TEST_SKIP,
	IOU_TEST_FAIL,
};

struct iou_test {
	/**
	 * name - The name of the testcase.
	 */
	const char *name;

	/**
	 * description - A description of the testcase.
	 */
	const char *description;

	/**
	 * setup - Setup callback to initialize the test.
	 * @ctx: A pointer to a context object that will be passed to run
	 *       and cleanup.
	 *
	 * Return: IOU_TEST_PASS if setup was successful, IOU_TEST_SKIP
	 *         if the test should be skipped, or IOU_TEST_FAIL if the
	 *         test should be marked as failed.
	 */
	enum iou_test_status (*setup)(void **ctx);

	/**
	 * run - The main test function.
	 * @ctx: Context object returned from setup().
	 *
	 * Return: IOU_TEST_PASS if the test passed, or IOU_TEST_FAIL
	 *         if it failed.
	 */
	enum iou_test_status (*run)(void *ctx);

	/**
	 * cleanup - Cleanup callback.
	 * @ctx: Context object returned from setup().
	 */
	void (*cleanup)(void *ctx);
};

void iou_test_register(struct iou_test *test);

#define REGISTER_IOU_TEST(__test)					\
	__attribute__((constructor))					\
	static void __test##_register(void)				\
	{								\
		iou_test_register(&(__test));				\
	}

#define IOU_BUG(__cond, __fmt, ...)					\
	do {								\
		if (__cond) {						\
			fprintf(stderr, "FATAL (%s:%d): " __fmt "\n",	\
				__FILE__, __LINE__,			\
				##__VA_ARGS__);				\
			exit(1);					\
		}							\
	} while (0)

#define IOU_BUG_ON(__cond) IOU_BUG(__cond, "BUG: %s", #__cond)

#define IOU_FAIL(__fmt, ...)						\
	do {								\
		fprintf(stderr, "FAIL (%s:%d): " __fmt "\n",		\
			__FILE__, __LINE__, ##__VA_ARGS__);		\
		return IOU_TEST_FAIL;					\
	} while (0)

#define IOU_FAIL_IF(__cond, __fmt, ...)					\
	do {								\
		if (__cond)						\
			IOU_FAIL(__fmt, ##__VA_ARGS__);			\
	} while (0)

#define IOU_ERR(__fmt, ...)						\
	fprintf(stderr, "ERR: " __fmt "\n", ##__VA_ARGS__)

#define IOU_INFO(__fmt, ...)						\
	fprintf(stdout, "INFO: " __fmt "\n", ##__VA_ARGS__)

#endif /* __IOU_TEST_H__ */

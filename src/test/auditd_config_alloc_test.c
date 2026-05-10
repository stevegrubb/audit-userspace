/*
 * auditd_config_alloc_test.c - allocation failure tests for auditd parser
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "config.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void test_audit_msg(int priority, const char *fmt, ...)
{
	(void)priority;
	(void)fmt;
}

char *test_audit_strsplit(char *s)
{
	(void)s;
	return NULL;
}

long test_time_string_to_seconds(const char *time_string,
				 const char *subsystem, int line)
{
	(void)time_string;
	(void)subsystem;
	(void)line;
	return 0;
}

static long alloc_count;
static long fail_at;

static void reset_allocs(long fail)
{
	alloc_count = 0;
	fail_at = fail;
}

static int should_fail(void)
{
	alloc_count++;
	return fail_at == alloc_count;
}

static void *test_malloc(size_t size)
{
	if (should_fail())
		return NULL;
	return malloc(size);
}

static char *test_strdup(const char *s)
{
	char *copy;
	size_t len;

	if (should_fail())
		return NULL;
	len = strlen(s) + 1;
	copy = malloc(len);
	if (copy)
		memcpy(copy, s, len);
	return copy;
}

static int test_asprintf(char **strp, const char *fmt, ...)
{
	va_list ap;
	int rc;

	if (should_fail()) {
		*strp = NULL;
		return -1;
	}

	va_start(ap, fmt);
	rc = vasprintf(strp, fmt, ap);
	va_end(ap);
	return rc;
}

#define audit_msg test_audit_msg
#define audit_strsplit test_audit_strsplit
#define time_string_to_seconds test_time_string_to_seconds
#define malloc test_malloc
#define strdup test_strdup
#define asprintf test_asprintf
#include "../auditd-config.c"
#undef asprintf
#undef strdup
#undef malloc
#undef time_string_to_seconds
#undef audit_strsplit
#undef audit_msg

static void test_name_preserves_old_value(void)
{
	struct daemon_conf config;
	struct nv_pair nv = { "name", "new-node", NULL };

	memset(&config, 0, sizeof(config));
	config.node_name = strdup("old-node");
	assert(config.node_name != NULL);

	reset_allocs(1);
	assert(name_parser(&nv, 1, &config) == 1);
	assert(strcmp(config.node_name, "old-node") == 0);

	free((void *)config.node_name);
}

static void test_log_file_preserves_old_value(void)
{
	struct daemon_conf config;
	struct nv_pair nv = { "log_file", "/tmp/audit-test.log", NULL };

	memset(&config, 0, sizeof(config));
	config.log_file = strdup("/tmp/old-audit.log");
	assert(config.log_file != NULL);
	log_test = TEST_SEARCH;

	reset_allocs(2);
	assert(log_file_parser(&nv, 1, &config) == 1);
	assert(strcmp(config.log_file, "/tmp/old-audit.log") == 0);

	free((void *)config.log_file);
}

static void test_set_config_dir_preserves_old_value(void)
{
	reset_allocs(-1);
	assert(set_config_dir("/tmp/audit-old") == 0);
	assert(strcmp(config_dir, "/tmp/audit-old") == 0);
	assert(strcmp(config_file, "/tmp/audit-old/auditd.conf") == 0);

	reset_allocs(1);
	assert(set_config_dir("/tmp/audit-new") == 1);
	assert(strcmp(config_dir, "/tmp/audit-old") == 0);
	assert(strcmp(config_file, "/tmp/audit-old/auditd.conf") == 0);

	reset_allocs(-1);
	free((void *)config_dir);
	free(config_file);
	config_dir = NULL;
	config_file = NULL;
}

int main(void)
{
	reset_allocs(-1);
	test_name_preserves_old_value();
	test_log_file_preserves_old_value();
	test_set_config_dir_preserves_old_value();
	return 0;
}

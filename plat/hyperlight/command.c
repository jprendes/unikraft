/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2026, Unikraft GmbH and The Unikraft Authors. */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uk/alloc.h>
#include <uk/process.h>
#include <uk/sched.h>
#include <uk/syscall.h>
#include <hyperlight/step.h>

struct hl_command {
	__u64 id;
	char *storage, *cwd;
	char **argv, **env;
	unsigned int stdio;
	int ready, error;
};

static struct uk_thread *launcher;
static struct hl_command *pending;
static struct hl_command *launching;
static __u64 kill_id;

static void command_free(struct hl_command *command)
{
	uk_free(uk_alloc_get_default(), command->argv);
	uk_free(uk_alloc_get_default(), command->env);
	uk_free(uk_alloc_get_default(), command->storage);
	uk_free(uk_alloc_get_default(), command);
}

static void launch_ready(int error)
{
	launching->error = error;
	launching->ready = 1;
	uk_thread_wake(launcher);
}

static int command_exec_committed(void *arg)
{
	struct posix_process_execve_event_data *event = arg;

	if (launching && !launching->ready &&
	    event->thread->hyperlight_execution == launching->id)
		launch_ready(0);
	return UK_EVENT_HANDLED_CONT;
}

UK_EVENT_HANDLER(POSIX_PROCESS_EXECVE_COMMITTED_EVENT, command_exec_committed);

static int command_launch_exited(void *arg)
{
	struct posix_process_ppexit_event_data *event = arg;

	if (launching && !launching->ready && event->execution == launching->id)
		launch_ready(ECANCELED);
	return UK_EVENT_HANDLED_CONT;
}

POSIX_PROCESS_PPEXIT_HANDLER(command_launch_exited);

static __noreturn void command_child(void *argc __unused, void *argv __unused)
{
	struct hl_command *command = launching;
	int fd, error;

	for (unsigned int i = 0; i < 3; i++) {
		if (command->stdio & (1u << i)) {
			fd = hl_stdio_open(i);
			if (fd < 0) {
				error = -fd;
				goto failed;
			}
		} else {
			fd = open("/dev/null", i ? O_WRONLY : O_RDONLY);
			if (fd < 0) {
				error = errno;
				goto failed;
			}
		}
		if (fd != (int)i) {
			if (dup2(fd, i) < 0) {
				error = errno;
				close(fd);
				goto failed;
			}
			close(fd);
		} else if (fcntl(fd, F_SETFD, 0) < 0) {
			error = errno;
			goto failed;
		}
	}
	if (*command->cwd && chdir(command->cwd)) {
		error = errno;
		goto failed;
	}
	execve(command->argv[0], command->argv, command->env);
	error = errno;
failed:
	launch_ready(error);
	uk_syscall_e_exit_group(127);
	UK_BUG();
}

static __noreturn void command_loop(void)
{
	sigset_t mask;

	/* Leave process-directed signals to init's signalfd. */
	sigfillset(&mask);
	if (sigprocmask(SIG_BLOCK, &mask, NULL))
		UK_CRASH("cannot block command launcher signals: %d\n", errno);
	for (;;) {
		struct hl_command *command;
		int error;
		pid_t pid;

		while (!pending && !kill_id) {
			uk_thread_block(launcher);
			uk_sched_yield();
		}
		if (kill_id) {
			error = hl_execution_kill(kill_id);
			kill_id = 0;
			hl_command_complete(error);
			continue;
		}
		command = pending;
		pending = NULL;
		error = hl_execution_begin(command->id);
		if (error) {
			command_free(command);
			hl_command_complete(error);
			continue;
		}
		launching = command;
		pid = uk_posix_process_run(command_child, 0, NULL);
		if (pid < 0) {
			command->error = -pid;
		} else {
			while (!command->ready) {
				uk_thread_block(launcher);
				uk_sched_yield();
			}
		}
		hl_execution_started(pid, command->error);
		launching = NULL;
		command_free(command);
		hl_command_complete(0);
	}
}

int hl_command_service_init(void)
{
	int error;

	launcher = uk_sched_thread_create_fn0(uk_sched_current(), command_loop,
					     0, 0, false, false,
					     "hl-command", NULL, NULL);
	if (!launcher)
		return -ENOMEM;
	error = uk_posix_process_create_pthread(launcher);
	if (error)
		UK_CRASH("cannot attach command launcher to init: %d\n", error);
	return hl_command_service_ready();
}

void hl_command_service_shutdown(void)
{
	uk_sched_thread_terminate(launcher);
	launcher = NULL;
}

static char *command_field(char **cursor, char *end)
{
	char *start = *cursor;
	char *nul = memchr(start, 0, end - start);

	if (!nul)
		return NULL;
	*cursor = nul + 1;
	return start;
}

static int command_number(char **cursor, char *end, __u64 *value)
{
	char *field = command_field(cursor, end), *tail;

	if (!field || *field < '0' || *field > '9')
		return -EINVAL;
	errno = 0;
	*value = strtoull(field, &tail, 10);
	return errno || *tail ? -EINVAL : 0;
}

int hl_command_submit(const char *data, __sz len, int kill)
{
	struct hl_command *command;
	char *cursor, *end;
	__u64 version, argc, envc, stdio;

	if (!launcher || !hyperlight_execution_enabled)
		return -EOPNOTSUPP;
	if (pending || kill_id || launching)
		return -EBUSY;
	if (!data || !len)
		return -EINVAL;
	if (kill) {
		__u64 id = 0;

		for (__sz i = 0; i < len; i++) {
			if (data[i] < '0' || data[i] > '9' ||
			    id > ((__u64)-1 - (data[i] - '0')) / 10)
				return -EINVAL;
			id = id * 10 + data[i] - '0';
		}
		if (!id)
			return -EINVAL;
		kill_id = id;
		uk_thread_wake(launcher);
		return 0;
	}
	command = uk_calloc(uk_alloc_get_default(), 1, sizeof(*command));
	if (!command)
		return -ENOMEM;
	command->storage = uk_malloc(uk_alloc_get_default(), len);
	if (!command->storage)
		goto nomem;
	memcpy(command->storage, data, len);
	cursor = command->storage;
	end = cursor + len;
	if (command_number(&cursor, end, &version) || version != 8 ||
	    command_number(&cursor, end, &command->id) || !command->id ||
	    command_number(&cursor, end, &argc) || argc > len ||
	    command_number(&cursor, end, &envc) || envc > len ||
	    command_number(&cursor, end, &stdio) || stdio > 7)
		goto invalid;
	command->stdio = stdio;
	command->cwd = command_field(&cursor, end);
	command->argv = uk_calloc(uk_alloc_get_default(), argc + 2, sizeof(char *));
	command->env = uk_calloc(uk_alloc_get_default(), envc + 1, sizeof(char *));
	if (!command->argv || !command->env)
		goto nomem;
	if (!command->cwd)
		goto invalid;
	for (__u64 i = 0; i <= argc; i++) {
		command->argv[i] = command_field(&cursor, end);
		if (!command->argv[i])
			goto invalid;
	}
	for (__u64 i = 0; i < envc; i++) {
		command->env[i] = command_field(&cursor, end);
		if (!command->env[i])
			goto invalid;
	}
	if (cursor != end || command->argv[0][0] != '/')
		goto invalid;
	pending = command;
	uk_thread_wake(launcher);
	return 0;
nomem:
	command_free(command);
	return -ENOMEM;
invalid:
	command_free(command);
	return -EINVAL;
}

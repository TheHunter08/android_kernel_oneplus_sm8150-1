/* drivers/misc/lowmemorykiller.c
 *
 * The lowmemorykiller driver lets user-space specify a set of memory thresholds
 * where processes with a range of oom_score_adj values will get killed. Specify
 * the minimum oom_score_adj values in
 * /sys/module/lowmemorykiller/parameters/adj and the number of free pages in
 * /sys/module/lowmemorykiller/parameters/minfree. Both files take a comma
 * separated list of numbers in ascending order.
 *
 * For example, write "0,8" to /sys/module/lowmemorykiller/parameters/adj and
 * "1024,4096" to /sys/module/lowmemorykiller/parameters/minfree to kill
 * processes with a oom_score_adj value of 8 or higher when the free memory
 * drops below 4096 pages and kill processes with a oom_score_adj value of 0 or
 * higher when the free memory drops below 1024 pages.
 *
 * The driver considers memory used for caches to be free, but if a large
 * percentage of the cached memory is locked this can be very inaccurate
 * and processes may not get killed until the normal oom killer is triggered.
 *
 * Copyright (C) 2007-2008 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/oom.h>
#include <linux/sched.h>
#include <linux/swap.h>
#include <linux/rcupdate.h>
#include <linux/profile.h>
#include <linux/notifier.h>

#define CREATE_TRACE_POINTS
#include "trace/lowmemorykiller.h"

static u32 lowmem_debug_level = 1;
static short lowmem_adj[6] = {
	0,
	1,
	6,
	12,
};

static int lowmem_adj_size = 4;
static int lowmem_minfree[6] = {
	3 * 512,	/* 6MB */
	2 * 1024,	/* 8MB */
	4 * 1024,	/* 16MB */
	16 * 1024,	/* 64MB */
};

static int lowmem_minfree_size = 4;

static unsigned long lowmem_deathpending_timeout;

/*  bin.zhong@ASTI add for CONFIG_SMART_BOOST */
unsigned long get_max_minfree(void)
{
	return (unsigned long)lowmem_minfree[lowmem_minfree_size - 1];
}

#define lowmem_print(level, x...)			\
	do {						\
		if (lowmem_debug_level >= (level))	\
			pr_info(x);			\
	} while (0)

static unsigned long lowmem_count(struct shrinker *s,
				  struct shrink_control *sc)
{
	return global_node_page_state(NR_ACTIVE_ANON) +
		global_node_page_state(NR_ACTIVE_FILE) +
		global_node_page_state(NR_INACTIVE_ANON) +
		global_node_page_state(NR_INACTIVE_FILE);
}

static unsigned long lowmem_scan(struct shrinker *s, struct shrink_control *sc)
{
	struct task_struct *tsk;
	struct task_struct *selected = NULL;
	unsigned long rem = 0;
	int tasksize;
	int i;
	short min_score_adj = OOM_SCORE_ADJ_MAX + 1;
	int minfree = 0;
	int selected_tasksize = 0;
	short selected_oom_score_adj;
	int array_size = ARRAY_SIZE(lowmem_adj);
	int other_free = global_page_state(NR_FREE_PAGES) - totalreserve_pages;
	int other_file = global_node_page_state(NR_FILE_PAGES) -
				global_node_page_state(NR_SHMEM) -
				global_node_page_state(NR_UNEVICTABLE) -
				total_swapcache_pages();

	if (lowmem_adj_size < array_size)
		array_size = lowmem_adj_size;
	if (lowmem_minfree_size < array_size)
		array_size = lowmem_minfree_size;
	for (i = 0; i < array_size; i++) {
		minfree = lowmem_minfree[i];
		if (other_free < minfree && other_file < minfree) {
			min_score_adj = lowmem_adj[i];
			break;
		}
	}

	lowmem_print(3, "lowmem_scan %lu, %x, ofree %d %d, ma %hd\n",
		     sc->nr_to_scan, sc->gfp_mask, other_free,
		     other_file, min_score_adj);

#ifdef CONFIG_ADJ_CHAIN
	if (unlikely(selftest_running)) {
		min_score_adj = selftest_min_score_adj;
		goto selftest_bypass;
	}
#endif
	if (min_score_adj == OOM_SCORE_ADJ_MAX + 1) {
		lowmem_print(5, "lowmem_scan %lu, %x, return 0\n",
			     sc->nr_to_scan, sc->gfp_mask);
		return 0;
	}

#ifdef CONFIG_ADJ_CHAIN
selftest_bypass:
#endif
	selected_oom_score_adj = min_score_adj;

	rcu_read_lock();
#ifdef CONFIG_ADJ_CHAIN
	/* record for each time lmk scan's min_score_adj */
	bkws[0].min_score_adj = min_score_adj;

	/* marker for select begin */
	time_measure_marker(MEASURE_START_MARKER, NULL, NULL);

	if (quick_select_enable) {
		if (lowmem_quick_select_next(min_score_adj,
				&selected, batch_kill_enable, bkws,
				&selected_tasksize, &selected_oom_score_adj))
			return 0;

		if (selected || !batch_kill_empty(bkws))
			goto quick_select_fast;
		else if (trust_adj_chain) {
			/* marker for select end */
			bkws[0].missed = LMK_ADJ_CHAIN_MISSED;
			time_measure_marker(MEASURE_END_MARKER, selected, bkws);

			/*
			 * since trust adj chain, then we don't need to search tasklist again.
			 * Basically, if candidate task can't be found in adj chain,
			 * it should not be found in tasklist neither.
			 */
			trace_almk_shrink(1, ret, other_free, other_file, 0);
			rcu_read_unlock();
			lowmem_print(4, "%s %lu, %x, return %lu\n",
					__func__, sc->nr_to_scan, sc->gfp_mask, rem);
			mutex_unlock(&scan_mutex);
			return rem;
		}
	}
#endif
	for_each_process(tsk) {
		struct task_struct *p;
		short oom_score_adj;
#ifdef CONFIG_ADJ_CHAIN
		/* record for scan cnt */
		++bkws[0].scan;
#endif

		if (tsk->flags & PF_KTHREAD)
			continue;

		p = find_lock_task_mm(tsk);
		if (!p)
			continue;

		if (task_lmk_waiting(p) &&
		    time_before_eq(jiffies, lowmem_deathpending_timeout)) {
			task_unlock(p);
			rcu_read_unlock();
			return 0;
		}
		oom_score_adj = p->signal->oom_score_adj;
		if (oom_score_adj < min_score_adj) {
			task_unlock(p);
			continue;
		}
		tasksize = get_mm_rss(p->mm);
		task_unlock(p);
		if (tasksize <= 0)
			continue;
		if (selected) {
			if (oom_score_adj < selected_oom_score_adj)
				continue;
			if (oom_score_adj == selected_oom_score_adj &&
			    tasksize <= selected_tasksize)
				continue;
		}
		selected = p;
		selected_tasksize = tasksize;
		selected_oom_score_adj = oom_score_adj;
		lowmem_print(2, "select '%s' (%d), adj %hd, size %d, to kill\n",
			     p->comm, p->pid, oom_score_adj, tasksize);
	}
#ifdef CONFIG_ADJ_CHAIN
	/* adj chain diagnose */
	if (!selected) {
		/* which is good because it expected result */
		mt = LMK_BOTH_MISSED;
	} else {
		struct list_head *h;
		struct task_struct *tsk;
		bool found = false;

		if (!quick_select_enable)
			goto bypass_diagnose;

		mt = LMK_ADJ_CHAIN_MISSED;

		lowmem_print(3, "missing task '%s' (%d) adj %hd, adj_chain_status(%d), size %d, "
				"missed from adj chain, run diagnose\n",
				selected->comm,
				selected->pid,
				selected_oom_score_adj,
				selected->adj_chain_status,
				selected_tasksize);

		if (!found) {
			if (selected->adj_chain_status) {
				lowmem_print(3,
					"missing task adj_chain_status(%d), under updating, "
					"should be reattach to adj chain %hd later, don't worry!\n",
					selected->adj_chain_status,
					selected_oom_score_adj);
				found = true;
				mt = LMK_NOTHING_MISSED;
			}
		}

		if (!found) {
			list_for_each(h, &adj_chain[__adjc(selected_oom_score_adj)]) {
				tsk = get_task_struct_adj_chain_rcu(h);
				if (tsk == selected) {
					lowmem_print(3,
								"missing task exists in other adj chain\n");
					found = true;
					mt = LMK_NOTHING_MISSED;
					break;
				}
			}
		}

		if (!found) {
		/* worst case to search each adj chain for missing task */
			int cur_high = __adjc(1000);

			lowmem_print(3,
					"missing task not exists adj chain,search for all adj chain\n");
			for (; cur_high >= 0; --cur_high) {
				if (!list_empty(&adj_chain[cur_high])) {
					list_for_each(h, &adj_chain[cur_high]) {
						tsk = get_task_struct_adj_chain_rcu(h);
						if (tsk == selected) {
							lowmem_print(3,
									"missing task finally found with in adj chain %d\n",
									__adjr(cur_high));
							found = true;
							mt = LMK_NOTHING_MISSED;
							break;
						}
					}
				}
				if (found)
					break;
			}
		}

		/* missing someone ... oops */
		if (!found) {
			lowmem_print(1, "missing task '%s' (%d) adj %hd, adj_chain_status(%d)\n",
					selected->comm, selected->pid, selected_oom_score_adj,
					selected->adj_chain_status);
		}

		/* leave selected task NULL for further debugging */
		selected = NULL;
	}

bypass_diagnose:
	/* record missing task analysis result */
	bkws[0].missed = mt;

quick_select_fast:
	/* marker for select end */
	time_measure_marker(MEASURE_END_MARKER, selected, bkws);

	if (batch_kill_enable && !batch_kill_empty(bkws))
		return lowmem_batch_kill(bkws, sc, minfree, other_file,
						other_free, min_score_adj);
#endif
	if (selected) {
		long cache_size = other_file * (long)(PAGE_SIZE / 1024);
		long cache_limit = minfree * (long)(PAGE_SIZE / 1024);
		long free = other_free * (long)(PAGE_SIZE / 1024);

		task_lock(selected);
		send_sig(SIGKILL, selected, 0);
		if (selected->mm)
			task_set_lmk_waiting(selected);
		task_unlock(selected);
		trace_lowmemory_kill(selected, cache_size, cache_limit, free);
		lowmem_print(1, "Killing '%s' (%d) (tgid %d), adj %hd,\n"
				 "   to free %ldkB on behalf of '%s' (%d) because\n"
				 "   cache %ldkB is below limit %ldkB for oom_score_adj %hd\n"
				 "   Free memory is %ldkB above reserved\n",
			     selected->comm, selected->pid, selected->tgid,
			     selected_oom_score_adj,
			     selected_tasksize * (long)(PAGE_SIZE / 1024),
			     current->comm, current->pid,
			     cache_size, cache_limit,
			     min_score_adj,
			     free);
		lowmem_deathpending_timeout = jiffies + HZ;
		rem += selected_tasksize;
	}

	lowmem_print(4, "lowmem_scan %lu, %x, return %lu\n",
		     sc->nr_to_scan, sc->gfp_mask, rem);
	rcu_read_unlock();
	return rem;
}

static struct shrinker lowmem_shrinker = {
	.scan_objects = lowmem_scan,
	.count_objects = lowmem_count,
	.seeks = DEFAULT_SEEKS * 16
};

static int __init lowmem_init(void)
{
	register_shrinker(&lowmem_shrinker);
	return 0;
}
device_initcall(lowmem_init);

#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_AUTODETECT_OOM_ADJ_VALUES
static short lowmem_oom_adj_to_oom_score_adj(short oom_adj)
{
	if (oom_adj == OOM_ADJUST_MAX)
		return OOM_SCORE_ADJ_MAX;
	else
		return (oom_adj * OOM_SCORE_ADJ_MAX) / -OOM_DISABLE;
}

static void lowmem_autodetect_oom_adj_values(void)
{
	int i;
	short oom_adj;
	short oom_score_adj;
	int array_size = ARRAY_SIZE(lowmem_adj);

	if (lowmem_adj_size < array_size)
		array_size = lowmem_adj_size;

	if (array_size <= 0)
		return;

	oom_adj = lowmem_adj[array_size - 1];
	if (oom_adj > OOM_ADJUST_MAX)
		return;

	oom_score_adj = lowmem_oom_adj_to_oom_score_adj(oom_adj);
	if (oom_score_adj <= OOM_ADJUST_MAX)
		return;

	lowmem_print(1, "lowmem_shrink: convert oom_adj to oom_score_adj:\n");
	for (i = 0; i < array_size; i++) {
		oom_adj = lowmem_adj[i];
		oom_score_adj = lowmem_oom_adj_to_oom_score_adj(oom_adj);
		lowmem_adj[i] = oom_score_adj;
		lowmem_print(1, "oom_adj %d => oom_score_adj %d\n",
			     oom_adj, oom_score_adj);
	}
}

static int lowmem_adj_array_set(const char *val, const struct kernel_param *kp)
{
	int ret;

	ret = param_array_ops.set(val, kp);

	/* HACK: Autodetect oom_adj values in lowmem_adj array */
	lowmem_autodetect_oom_adj_values();

	return ret;
}

static int lowmem_adj_array_get(char *buffer, const struct kernel_param *kp)
{
	return param_array_ops.get(buffer, kp);
}

static void lowmem_adj_array_free(void *arg)
{
	param_array_ops.free(arg);
}

static struct kernel_param_ops lowmem_adj_array_ops = {
	.set = lowmem_adj_array_set,
	.get = lowmem_adj_array_get,
	.free = lowmem_adj_array_free,
};

static const struct kparam_array __param_arr_adj = {
	.max = ARRAY_SIZE(lowmem_adj),
	.num = &lowmem_adj_size,
	.ops = &param_ops_short,
	.elemsize = sizeof(lowmem_adj[0]),
	.elem = lowmem_adj,
};
#endif

/*
 * not really modular, but the easiest way to keep compat with existing
 * bootargs behaviour is to continue using module_param here.
 */
module_param_named(cost, lowmem_shrinker.seeks, int, 0644);
#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_AUTODETECT_OOM_ADJ_VALUES
module_param_cb(adj, &lowmem_adj_array_ops,
		.arr = &__param_arr_adj,
		0644);
__MODULE_PARM_TYPE(adj, "array of short");
#else
module_param_array_named(adj, lowmem_adj, short, &lowmem_adj_size, 0644);
#endif
module_param_array_named(minfree, lowmem_minfree, uint, &lowmem_minfree_size,
			 0644);
module_param_named(debug_level, lowmem_debug_level, uint, 0644);

#ifdef CONFIG_ADJ_CHAIN
static int selftest_store(const char *buf, const struct kernel_param *kp)
{
	unsigned int val;
	unsigned int min_score_adj = 900;
	long freeable;
	struct shrink_control sc = {
		.gfp_mask = GFP_KERNEL,
		.nid = 0,
		.memcg = NULL,
	};

	if (sscanf(buf, "%u %u\n", &val, &min_score_adj) <= 0)
		return -EINVAL;

	if (val < 1 || val > BATCH_KILL_MAX_CNT || min_score_adj < 352 || min_score_adj > 1000) {
		lowmem_print(1, "selftest EINVAL\n");
		return -EINVAL;
	}

	batch_kill_cnt = val;
	selftest_min_score_adj = min_score_adj;
	selftest_running = true;
	freeable = lowmem_count(NULL, NULL);
	if (freeable) {
		lowmem_print(1, "selftest set batch kill cnt to %u, min_score_adj %d\n", val, min_score_adj);
		lowmem_scan(NULL, &sc);
	}
	batch_kill_cnt = 1;
	selftest_running = false;
	return 0;
}

static struct kernel_param_ops selftest_ops = {
	.set = selftest_store,
};
module_param_cb(selftest, &selftest_ops, NULL, 0200);
#endif

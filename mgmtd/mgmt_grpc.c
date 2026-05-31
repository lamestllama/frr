// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * mgmtd gRPC northbound integration.
 *
 * Bridges YANG RPC dispatch from lib/northbound_grpc.cpp into the same
 * backend transaction machinery the vtysh `mgmt rpc` command uses
 * (see mgmtd/mgmt_fe_adapter.c::fe_session_handle_rpc).  Without this,
 * gRPC Execute on mgmtd has no local callback to dispatch against and
 * fails at libyang's leafref validation before the handler is ever
 * invoked.
 */

#include <zebra.h>

#include "darr.h"
#include "libfrr.h"
#include "northbound.h"
#include "yang.h"

#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_be_adapter.h"
#include "mgmtd/mgmt_memory.h"
#include "mgmtd/mgmt_txn.h"

#define _dbg(fmt, ...)                                                                            \
	DEBUGD(&mgmt_debug_fe, "GRPC-RPC: %s: " fmt, __func__, ##__VA_ARGS__)
#define _log_err(fmt, ...) zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)

struct mgmt_grpc_rpc_req {
	pthread_mutex_t mtx;
	pthread_cond_t cond;
	struct event *timeout;
	unsigned int refcnt;
	bool done;

	char *xpath;
	struct lyd_node *input;
	struct lyd_node *output;
	int error;
	char *errstr;
	nb_rpc_dispatch_done_cb done_cb;
	void *done_arg;
};

static uint64_t mgmt_grpc_session_id = UINT64_MAX / 2;
static uint64_t mgmt_grpc_req_id;
static pthread_t mgmt_grpc_main_pthread;

static void mgmt_grpc_rpc_req_put(struct mgmt_grpc_rpc_req *req)
{
	bool destroy;

	pthread_mutex_lock(&req->mtx);
	assert(req->refcnt);
	destroy = --req->refcnt == 0;
	pthread_mutex_unlock(&req->mtx);

	if (!destroy)
		return;

	lyd_free_all(req->input);
	lyd_free_all(req->output);
	darr_free(req->errstr);
	XFREE(MTYPE_MGMTD_GRPC_RPC, req->xpath);
	pthread_cond_destroy(&req->cond);
	pthread_mutex_destroy(&req->mtx);
	XFREE(MTYPE_MGMTD_GRPC_RPC, req);
}

static void mgmt_grpc_rpc_complete(struct mgmt_grpc_rpc_req *req, int error,
				   const char *errstr,
				   const struct lyd_node *result)
{
	nb_rpc_dispatch_done_cb done_cb = NULL;
	void *done_arg = NULL;
	struct lyd_node *output = NULL;
	LY_ERR err = LY_SUCCESS;
	int cb_error;
	const char *cb_errstr;

	pthread_mutex_lock(&req->mtx);

	if (req->done)
		goto done;

	req->error = error;
	if (errstr)
		darr_in_strdup(req->errstr, errstr);
	if (!error && result)
		err = lyd_dup_siblings(result, NULL,
				       LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS,
				       &req->output);
	if (err) {
		req->error = -EINVAL;
		darr_in_strdup(req->errstr, "Cannot copy RPC result");
	}
	req->done = true;
	done_cb = req->done_cb;
	done_arg = req->done_arg;
	if (done_cb) {
		output = req->output;
		req->output = NULL;
		cb_error = req->error;
		cb_errstr = req->errstr;
	} else
		pthread_cond_signal(&req->cond);

done:
	pthread_mutex_unlock(&req->mtx);

	if (done_cb)
		done_cb(cb_error, cb_errstr, output, done_arg);
}

static bool mgmt_grpc_rpc_is_done(struct mgmt_grpc_rpc_req *req)
{
	bool done;

	pthread_mutex_lock(&req->mtx);
	done = req->done;
	pthread_mutex_unlock(&req->mtx);

	return done;
}

static void mgmt_grpc_rpc_timeout(struct event *event)
{
	struct mgmt_grpc_rpc_req *req = EVENT_ARG(event);

	mgmt_grpc_rpc_complete(req, -ETIMEDOUT, "RPC timed out", NULL);
}

static void mgmt_grpc_rpc_done(uint64_t txn_id, uint64_t req_id, int error,
			       const char *errstr, LYD_FORMAT result_type,
			       bool restconf, const struct lyd_node *result,
			       void *arg)
{
	struct mgmt_grpc_rpc_req *req = arg;

	(void)txn_id;
	(void)req_id;
	(void)result_type;
	(void)restconf;

	mgmt_grpc_rpc_complete(req, error, errstr, result);
	mgmt_grpc_rpc_req_put(req);
}

static uint64_t mgmt_grpc_next_session_id(void)
{
	return mgmt_grpc_session_id++;
}

static uint64_t mgmt_grpc_next_req_id(void)
{
	return ++mgmt_grpc_req_id;
}

static void mgmt_grpc_rpc_event(struct event *event)
{
	struct mgmt_grpc_rpc_req *req = EVENT_ARG(event);
	const struct lysc_node *snode;
	uint64_t session_id;
	uint64_t txn_id;
	uint64_t req_id;
	uint64_t clients;
	char *data = NULL;
	LY_ERR err;

	if (mgmt_grpc_rpc_is_done(req)) {
		mgmt_grpc_rpc_req_put(req);
		return;
	}

	snode = lys_find_path(ly_native_ctx, NULL, req->xpath, 0);
	if (!snode) {
		mgmt_grpc_rpc_complete(req, -ENOENT, "No such RPC path", NULL);
		mgmt_grpc_rpc_req_put(req);
		return;
	}

	if (snode->nodetype != LYS_RPC && snode->nodetype != LYS_ACTION) {
		mgmt_grpc_rpc_complete(req, -EINVAL,
				       "Path is not an RPC or action", NULL);
		mgmt_grpc_rpc_req_put(req);
		return;
	}

	clients = mgmt_be_interested_clients(req->xpath,
					     MGMT_BE_XPATH_SUBSCR_TYPE_RPC,
					     "RPC");
	if (!clients) {
		mgmt_grpc_rpc_complete(req, -ENOENT,
				       "No backend implements RPC path", NULL);
		mgmt_grpc_rpc_req_put(req);
		return;
	}

	err = lyd_print_mem(&data, req->input, LYD_JSON, LYD_PRINT_SHRINK);
	if (err) {
		mgmt_grpc_rpc_complete(req, -EINVAL,
				       "Cannot serialize RPC input", NULL);
		mgmt_grpc_rpc_req_put(req);
		return;
	}

	session_id = mgmt_grpc_next_session_id();
	txn_id = mgmt_create_txn(session_id, MGMTD_TXN_TYPE_RPC);
	if (txn_id == MGMTD_TXN_ID_NONE) {
		free(data);
		_log_err("failed to create RPC txn for xpath=%s", req->xpath);
		mgmt_grpc_rpc_complete(req, -EINPROGRESS,
				       "Failed to create RPC transaction", NULL);
		mgmt_grpc_rpc_req_put(req);
		return;
	}

	req_id = mgmt_grpc_next_req_id();
	_dbg("created RPC txn-id=%" PRIu64 " req-id=%" PRIu64 " for xpath=%s",
	     txn_id, req_id, req->xpath);
	mgmt_txn_send_rpc_notify(txn_id, req_id, clients, LYD_JSON, false,
				 req->xpath, data, strlen(data) + 1,
				 mgmt_grpc_rpc_done, req);
	free(data);
}

/*
 * Synchronous fallback for callers that do not use the async dispatch hook.
 *
 * gRPC Execute uses nb_rpc_dispatch_async(), so it returns to the completion
 * queue while mgmtd waits for backend replies.  Keep this path for legacy
 * synchronous dispatch users.  If such a caller is on the main thread, drive
 * the event loop manually so the transaction callback can fire.  The extra
 * five seconds mirror the pthread wait below and give mgmtd's own RPC
 * transaction timeout a chance to report first.
 */
static void mgmt_grpc_rpc_wait_main(struct mgmt_grpc_rpc_req *req)
{
	struct event event;

	event_add_timer(mm->master, mgmt_grpc_rpc_timeout, req,
			MGMTD_TXN_RPC_MAX_DELAY_SEC + 5, &req->timeout);

	while (!mgmt_grpc_rpc_is_done(req) && event_fetch(mm->master, &event))
		event_call(&event);

	if (!mgmt_grpc_rpc_is_done(req))
		mgmt_grpc_rpc_complete(req, -ESHUTDOWN, "RPC interrupted", NULL);

	event_cancel(&req->timeout);
}

static int mgmt_grpc_rpc_dispatch(const char *xpath, const struct lyd_node *input,
				  struct lyd_node **output, char *errmsg,
				  size_t errmsg_len)
{
	struct mgmt_grpc_rpc_req *req;
	struct timespec ts;
	LY_ERR err;
	int ret = 0;

	_dbg("dispatching gRPC RPC xpath=%s", xpath);

	req = XCALLOC(MTYPE_MGMTD_GRPC_RPC, sizeof(*req));
	pthread_mutex_init(&req->mtx, NULL);
	pthread_cond_init(&req->cond, NULL);
	req->refcnt = 1;
	req->xpath = XSTRDUP(MTYPE_MGMTD_GRPC_RPC, xpath);
	err = lyd_dup_siblings(input, NULL,
			       LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS,
			       &req->input);
	if (err) {
		snprintf(errmsg, errmsg_len, "Cannot copy RPC input");
		mgmt_grpc_rpc_req_put(req);
		return -EINVAL;
	}

	req->refcnt = 2;
	event_add_event(mm->master, mgmt_grpc_rpc_event, req, 0, NULL);

	if (pthread_equal(pthread_self(), mgmt_grpc_main_pthread))
		mgmt_grpc_rpc_wait_main(req);
	else {
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += MGMTD_TXN_RPC_MAX_DELAY_SEC + 5;

		pthread_mutex_lock(&req->mtx);
		while (!req->done) {
			ret = pthread_cond_timedwait(&req->cond, &req->mtx,
						     &ts);
			if (ret == ETIMEDOUT) {
				req->error = -ETIMEDOUT;
				darr_in_strdup(req->errstr, "RPC timed out");
				req->done = true;
				break;
			}
		}
		pthread_mutex_unlock(&req->mtx);
	}

	pthread_mutex_lock(&req->mtx);
	ret = req->error;
	if (req->errstr)
		strlcpy(errmsg, req->errstr, errmsg_len);
	if (!ret) {
		*output = req->output;
		req->output = NULL;
	}
	pthread_mutex_unlock(&req->mtx);

	mgmt_grpc_rpc_req_put(req);
	return ret;
}

static int mgmt_grpc_rpc_dispatch_async(const char *xpath,
					const struct lyd_node *input,
					nb_rpc_dispatch_done_cb done, void *arg,
					char *errmsg, size_t errmsg_len)
{
	struct mgmt_grpc_rpc_req *req;
	LY_ERR err;

	_dbg("dispatching async gRPC RPC xpath=%s", xpath);

	req = XCALLOC(MTYPE_MGMTD_GRPC_RPC, sizeof(*req));
	pthread_mutex_init(&req->mtx, NULL);
	pthread_cond_init(&req->cond, NULL);
	req->refcnt = 1;
	req->done_cb = done;
	req->done_arg = arg;
	req->xpath = XSTRDUP(MTYPE_MGMTD_GRPC_RPC, xpath);
	err = lyd_dup_siblings(input, NULL,
			       LYD_DUP_RECURSIVE | LYD_DUP_WITH_FLAGS,
			       &req->input);
	if (err) {
		snprintf(errmsg, errmsg_len, "Cannot copy RPC input");
		mgmt_grpc_rpc_req_put(req);
		return -EINVAL;
	}

	event_add_event(mm->master, mgmt_grpc_rpc_event, req, 0, NULL);
	return 0;
}

void mgmt_grpc_init(void)
{
	mgmt_grpc_main_pthread = pthread_self();
	nb_rpc_dispatch_set(mgmt_grpc_rpc_dispatch);
	nb_rpc_dispatch_async_set(mgmt_grpc_rpc_dispatch_async);
}

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stddef.h>
#include <assert.h>


#include <net/if.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>

#include <netlink/netlink.h>
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/socket.h>
#include <netlink/msg.h>


#include "hc_list.h"

// http://www.infradead.org/~tgr/libnl/doc/api/nl_8c_source.html#l00469
// https://github.com/Robpol86/libnl/blob/master/example_c/scan_access_points.c
// https://git.kernel.org/pub/scm/linux/kernel/git/jberg/iw.git/tree/scan.c

// TODO: add timeout
typedef struct hc_list_int_node
{
    hc_list_node node;
    union {
        size_t sz;
        intptr_t i;
        uintptr_t ui;
        void *ptr;
    } data;
    unsigned char suffix[];
} hc_list_int_node;

static inline hc_list_int_node *hc_list_int_node_from_hc_list_node_shift(
    hc_list_node *obj)
{
    return (hc_list_int_node *)((char *)obj - offsetof(hc_list_int_node, node));
}

static inline void hc_list_int_node_from_hc_list_node_mfree_thunk(hc_list_node *obj)
{
    hc_list_int_node *int_node 
        = hc_list_int_node_from_hc_list_node_shift(obj);
    free(int_node);
}
//*/

typedef struct wn_nl80211_ctx
{
    struct nl_sock *sock;
    int nl80211_family_id;
    struct {
        int scan;
    } grp_id;
} wn_nl80211_ctx;

static int wn_nl80211_ctx_init(wn_nl80211_ctx *obj)
{        
    if (!(obj->sock = nl_socket_alloc()))
        goto ERR_EXIT; 
    
    if (genl_connect(obj->sock))
        goto ERR_EXIT_SOCK; 
    
    nl_socket_disable_seq_check(obj->sock);
    
    obj->nl80211_family_id
        = genl_ctrl_resolve(obj->sock, NL80211_GENL_NAME);
    
    if (obj->nl80211_family_id < 0)
	goto ERR_EXIT_SOCK;
    
    obj->grp_id.scan = genl_ctrl_resolve_grp(obj->sock, NL80211_GENL_NAME, 
        NL80211_MULTICAST_GROUP_SCAN);
    
    if (obj->grp_id.scan < 0)
	goto ERR_EXIT_SOCK;
    
    return 0;
    
ERR_EXIT_SOCK:
    nl_socket_free(obj->sock);
ERR_EXIT:
    return -1;
}

static int wn_nl80211_ctx_free (wn_nl80211_ctx *obj)
{
    nl_socket_free(obj->sock);
    return 0;
}

typedef struct wn_nl80211_sta_info_node
{
    hc_list_node node;

    
    unsigned char bssid[6];
    
    int32_t rssi_100dBm;
    uint32_t frequency_MHz;
    
    struct {
        struct {
            unsigned char data[32];
            size_t len;
        } ssid;
        hc_list_t channel_list;
        hc_list_t security_mode_list;
        
    } ie;
    
} wn_nl80211_sta_info_node;


wn_nl80211_sta_info_node *
  wn_nl80211_sta_info_node_from_hc_list_node_shift(hc_list_node *obj)
{
    return (wn_nl80211_sta_info_node *)((char *)obj - offsetof(
        wn_nl80211_sta_info_node, node)); 
}

static inline int wn_nl80211_sta_info_node_init_from_nl_msg(
    wn_nl80211_sta_info_node *obj, struct nl_msg *msg)
{
    struct genlmsghdr *gnlh;
    struct nlattr *root[NL80211_ATTR_MAX + 1]; /* at 0 */
    struct nlattr *bss_root[NL80211_BSS_MAX + 1]; 
    
    gnlh = nlmsg_data(nlmsg_hdr(msg));
    
    /* TODO: validate */
    
    nla_parse(root, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), 
        genlmsg_attrlen(gnlh, 0), NULL);
    
    nla_parse_nested(bss_root, NL80211_BSS_MAX/*top*/, 
        root[NL80211_ATTR_BSS], NULL);
    
    //memcpy(obj->ssid, nla_data(bss[NL80211_BSS_SSID]), sizeof(obj->bssid))
    
    *obj = (wn_nl80211_sta_info_node){ 0 };
    
    //ssid_cpy( , );
    
    memcpy(obj->bssid, nla_data(bss_root[NL80211_BSS_BSSID]), 
        sizeof(obj->bssid));
    
    obj->frequency_MHz = nla_get_u32(bss_root[NL80211_BSS_FREQUENCY]);
    obj->rssi_100dBm = nla_get_s32(bss_root[NL80211_BSS_SIGNAL_MBM]);
 
    
       
    hc_list_init(&obj->ie.channel_list);
    hc_list_init(&obj->ie.security_mode_list);
    return 0;
}

static inline 
    int wn_nl80211_sta_info_node_free(wn_nl80211_sta_info_node *obj)
{
    hc_list_for_each_node(hc_list_begin(&obj->ie.security_mode_list), 
        hc_list_end(&obj->ie.security_mode_list),
        hc_list_int_node_from_hc_list_node_mfree_thunk);
        
    hc_list_for_each_node(hc_list_begin(&obj->ie.channel_list), 
        hc_list_end(&obj->ie.channel_list),
        hc_list_int_node_from_hc_list_node_mfree_thunk);
    
    hc_list_destroy(&obj->ie.security_mode_list);
    hc_list_destroy(&obj->ie.channel_list);
    
    return 0;
}

static inline 
    int wn_nl80211_sta_info_node_mfree(wn_nl80211_sta_info_node *obj)
{
    int ret = wn_nl80211_sta_info_node_free(obj); 
    free(obj);
    return ret;
}

static inline
    void wn_nl80211_sta_info_node_from_hc_list_node_mfree(hc_list_node *ptr)
{
    wn_nl80211_sta_info_node *obj = 
        wn_nl80211_sta_info_node_from_hc_list_node_shift(ptr);
    
    wn_nl80211_sta_info_node_mfree(obj);
}


typedef struct wn_p_nl80211_scan_ctx
{
    int error_nl;
    char is_done; 
    char is_aborted;
} wn_p_nl80211_scan_ctx;

static inline 
int wn_p_nl80211_scan_ctx_init(wn_p_nl80211_scan_ctx *obj)
{
    *obj = (wn_p_nl80211_scan_ctx){ 0 };
    return 0;
}

static inline 
int wn_p_nl80211_scan_ctx_free(wn_p_nl80211_scan_ctx *obj)
{
    ((void)obj);
    return 0;
}

typedef struct wn_nl80211_scan_param_t
{
    hc_list_t frequency_list;
    hc_list_t ssid_list;    
    // TODO: bssid_list      
} wn_nl80211_scan_param_t;


static inline
    int wn_nl80211_scan_param_init(wn_nl80211_scan_param_t *obj)
{
    hc_list_init(&(*obj).frequency_list);   
    hc_list_init(&(*obj).ssid_list);
    return 0;
}

static inline
    int wn_nl80211_scan_param_free(wn_nl80211_scan_param_t *obj)
{
    hc_list_for_each_node(hc_list_begin(&obj->ssid_list),
        hc_list_end(&obj->ssid_list),
        hc_list_int_node_from_hc_list_node_mfree_thunk);
    
    hc_list_for_each_node(hc_list_begin(&obj->frequency_list),
        hc_list_end(&obj->frequency_list),
        hc_list_int_node_from_hc_list_node_mfree_thunk);
    
    hc_list_destroy(&(*obj).ssid_list);
    hc_list_destroy(&(*obj).frequency_list);   
    return 0;
}

static inline int wn_nl80211_scan_param_add_frequency(
    wn_nl80211_scan_param_t *obj, uint32_t freq)
{
    hc_list_int_node *node;
    
    if (!(node = (hc_list_int_node *)malloc(sizeof(hc_list_int_node))))
        return -1;
    
    (*node).data.ui = freq;
    
    hc_list_node_insert_before(hc_list_end(&obj->frequency_list), &node->node); 
    
    return 0;
}

static inline int wn_nl80211_scan_param_add_ssid(wn_nl80211_scan_param_t *obj, 
    const unsigned char *ssid, size_t sz)
{
    hc_list_int_node *node;
    
    if (!(node = (hc_list_int_node *)malloc(sizeof(hc_list_int_node) + sz)))
        return -1;
    
    (*node).data.sz = sz;
    memcpy(node->suffix, ssid, sz);
    
    hc_list_node_insert_before(hc_list_end(&obj->ssid_list), &node->node);
    return 0;
}

static inline int wn_nl80211_scan_param_add_ssid_str(
    wn_nl80211_scan_param_t *obj, const char *ssid_str) 
{
    return wn_nl80211_scan_param_add_ssid(obj, (const unsigned char *)ssid_str, 
        strlen(ssid_str) + 1); 
}

static int wn_p_nl80211_scan_callback_valid(struct nl_msg *, void *), 
           wn_p_nl80211_scan_callback_multipart_end(struct nl_msg *, void *),
           wn_p_nl80211_scan_callback_seq_check_noop(struct nl_msg *, void *);

static int wn_p_nl80211_scan_callback_handle_error(struct sockaddr_nl *, 
      struct nlmsgerr *, void *);


int wn_p_nl80211_scan_callback_valid(struct nl_msg *msg, void *arg)
{
    wn_p_nl80211_scan_ctx *ctx = (wn_p_nl80211_scan_ctx *) arg;
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    
    fprintf(stderr , "\n%d calling %s", 
        __LINE__, __PRETTY_FUNCTION__); 
    
    switch(gnlh->cmd)
    {
        case NL80211_CMD_NEW_SCAN_RESULTS:
            ctx->is_done = 1;
            fprintf(stderr, "\nNL80211_CMD_NEW_SCAN_RESULTS received");
            break;
        case NL80211_CMD_SCAN_ABORTED:
            ctx->is_aborted = 1;
            ctx->is_done = 1;
            fprintf(stderr, "\nNL80211_CMD_SCAN_ABORTED received");
            break;
    }
    
    return NL_OK;
}

int wn_p_nl80211_scan_callback_multipart_end(struct nl_msg *msg, void *arg)
{
    wn_p_nl80211_scan_ctx *ctx = (wn_p_nl80211_scan_ctx *) arg;
    
    fprintf(stderr , "\n%d calling %s", __LINE__, __PRETTY_FUNCTION__);
    ctx->is_done = 1;
    return NL_STOP; //
}

int wn_p_nl80211_scan_callback_seq_check_noop(struct nl_msg *msg, void *arg)
{
    ((void)msg,(void)arg);
    fprintf(stderr , "\n%d calling %s", __LINE__, __PRETTY_FUNCTION__); 
    return NL_OK;
}

int wn_p_nl80211_scan_callback_handle_error(struct sockaddr_nl *addr, 
      struct nlmsgerr *err, void *arg)
{
    wn_p_nl80211_scan_ctx *ctx = (wn_p_nl80211_scan_ctx *)arg;
    
    fprintf(stderr , "\n%d calling %s", __LINE__, __PRETTY_FUNCTION__); 
    
    ctx->error_nl = err->error;
    ctx->is_done = 1;
    
    return NL_STOP;
}

// wn_nl80211_sta_info_node
static int wn_nl80211_scan_perform(wn_nl80211_ctx *obj, const char *iface, 
    wn_nl80211_scan_param_t *param)
{
    int err;
    wn_p_nl80211_scan_ctx scan_ctx; 
    uint32_t iface_id; // 
    struct nl_msg *req_msg;
    struct nl_cb *callback_ptr; 
    
    err = 0; // lets wish the success to further functions calls.
    
    if (wn_p_nl80211_scan_ctx_init(&scan_ctx))
	    goto ERR_EXIT;
    
    if (!(iface_id = if_nametoindex(iface))) // 0 return on error
	    goto ERR_EXIT_SCAN_CTX;
    
    if (!(req_msg = nlmsg_alloc()))
	    goto ERR_EXIT_SCAN_CTX;
    
    if (!(callback_ptr = nl_cb_alloc(NL_CB_DEFAULT)))
        goto ERR_EXIT_REQ_MSG;
    

    if (!genlmsg_put(req_msg, 0, 0, (*obj).nl80211_family_id, 0, 0, 
        NL80211_CMD_TRIGGER_SCAN, 0))
    {
        fprintf(stderr, "\n%d, genlmsg_put: %d (%s)",__LINE__, err, 
            "failed");
        goto ERR_EXIT_CB_PTR;
    }
    // setting msg
    if ((err = nla_put_u32(req_msg, NL80211_ATTR_IFINDEX, iface_id)))
    {  
	    goto ERR_EXIT_CB_PTR;
    }
    
    /* @NL80211_ATTR_SCAN_SSIDS: *nested* attribute with SSIDs, leave out for passive
     *	scanning and include a zero-length SSID (wildcard(.?)) for wildcard scan */
    
    if (!hc_list_empty(&param->ssid_list))
    {
        struct nl_msg *ssid_attr_msg = nlmsg_alloc();
        size_t idx;
        if (!ssid_attr_msg)
            goto ERR_EXIT_CB_PTR;
        
        idx = 1;
        for (hc_list_node *curr = hc_list_begin(&param->ssid_list); 
            curr != hc_list_end(&param->ssid_list);
            curr = hc_list_node_next(curr), ++idx)
        {
            hc_list_int_node *node 
                = hc_list_int_node_from_hc_list_node_shift(curr);
	        
	        if ((err = nla_put(ssid_attr_msg, NL80211_SCHED_SCAN_MATCH_ATTR_SSID, node->data.sz, 
	            node->suffix))) 
            {
	            nlmsg_free(ssid_attr_msg);
                goto ERR_EXIT_CB_PTR;
            }
        }
          
	    if ((err = nla_put_nested(req_msg, NL80211_ATTR_SCAN_SSIDS, 
	        ssid_attr_msg)))
	    {
            nlmsg_free(ssid_attr_msg);
	        goto ERR_EXIT_CB_PTR;
	    }
	
	    nlmsg_free(ssid_attr_msg);
    }
    
    if (!hc_list_empty(&param->frequency_list))
    {
        struct nl_msg *freq_attr_msg = nlmsg_alloc();
        size_t idx;
    
        if (!freq_attr_msg)
            goto ERR_EXIT_CB_PTR;
        
        
        idx = 1;
        for (hc_list_node *curr = hc_list_begin(&param->frequency_list); 
            curr != hc_list_end(&param->frequency_list);
            curr = hc_list_node_next(curr), ++idx)
        {
            hc_list_int_node *node 
                = hc_list_int_node_from_hc_list_node_shift(curr);
	        
	        if ((err = nla_put_u32(freq_attr_msg, idx,
	            (uint32_t)node->data.ui))) 
            {
	            nlmsg_free(freq_attr_msg);
                goto ERR_EXIT_CB_PTR;
            }
        }
        
	    if ((err = nla_put_nested(req_msg, NL80211_ATTR_SCAN_FREQUENCIES, 
	        freq_attr_msg)))
	    {
            nlmsg_free(freq_attr_msg);
	        goto ERR_EXIT_CB_PTR;
	    }
	
	    nlmsg_free(freq_attr_msg);
    }  
    //*/
    
    // setting cb
    // http://www.infradead.org/~tgr/libnl/doc/core.html#core_netlink_fundamentals
    if ((err = nl_cb_set(callback_ptr, NL_CB_VALID, NL_CB_CUSTOM,
        wn_p_nl80211_scan_callback_valid, /* stop if cmd == new_scan or aborted */
        &scan_ctx)))
    {
        goto ERR_EXIT_CB_PTR;
    }
    
    if ((err = nl_cb_set(callback_ptr, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, 
	    wn_p_nl80211_scan_callback_seq_check_noop, NULL)))
    {
        goto ERR_EXIT_CB_PTR;
    }
    
    if ((err = nl_cb_set(callback_ptr, NL_CB_FINISH, NL_CB_CUSTOM, 
	    wn_p_nl80211_scan_callback_multipart_end, NULL)))
    {
        goto ERR_EXIT_CB_PTR;
    }
    
    if ((err = nl_cb_err(callback_ptr, NL_CB_CUSTOM,
        wn_p_nl80211_scan_callback_handle_error, &scan_ctx)))
    {
        goto ERR_EXIT_CB_PTR;
    }

    // start to receive scan group messages
    if (nl_socket_add_membership(obj->sock, (*obj).grp_id.scan))
    {
        goto ERR_EXIT_CB_PTR; 
    }
    
    fprintf(stderr , "\n%d, before nl_send_sync", __LINE__);
    
    // note that auto-ack is enabled by default; 
    // requesting ack can be set with nl_socket_(enable/disable)_auto_ack
    err = nl_send_sync(obj->sock, req_msg);
    req_msg = NULL;
    if (err) 
    {
        /* autocomplete (see room etc), send and wait for ack 
         *(NL_OK should be returned by default handler)*/
        fprintf(stderr, "\n%d, nl_send_sync: %d (%s)",__LINE__, err, 
            nl_geterror(-err));
        goto ERR_EXIT_SCAN_MEMBERSHIP;
    }
    
    // receiving msg
    fprintf(stderr , "\n%d, before nl_recvmsgs", __LINE__);
    do { // msges are not MULTIparted, so receiving in loop
	    if ((err = nl_recvmsgs(obj->sock, callback_ptr))) 
	    {
            fprintf(stderr, "\n%d, nl_recvmsgs: %d (%s)",__LINE__, err, 
                nl_geterror(-err));
            goto ERR_EXIT_SCAN_MEMBERSHIP;	
        }
    } while (!scan_ctx.is_done); 
    // set in wn_p_nl80211_scan_callback_valid or
    // wn_p_nl80211_scan_callback_multipart_end
    
    if (scan_ctx.is_aborted) // set in wn_p_nl80211_scan_callback_valid
	    goto ERR_EXIT_SCAN_MEMBERSHIP;
   
    if (scan_ctx.error_nl < 0) // set in wn_p_nl80211_scan_callback_handle_error
	    goto ERR_EXIT_SCAN_MEMBERSHIP; // 
    	
    nl_socket_drop_membership(obj->sock, (*obj).grp_id.scan);
    nl_cb_put(callback_ptr);
    wn_p_nl80211_scan_ctx_free(&scan_ctx);
    
    return 0;

ERR_EXIT_SCAN_MEMBERSHIP:
    nl_socket_drop_membership(obj->sock, (*obj).grp_id.scan);
ERR_EXIT_CB_PTR:
    nl_cb_put(callback_ptr);
ERR_EXIT_REQ_MSG:
    if (req_msg) nlmsg_free(req_msg);
ERR_EXIT_SCAN_CTX:    
    wn_p_nl80211_scan_ctx_free(&scan_ctx);
ERR_EXIT:
    return -1;
}


// TODO: revise err. han.
int wn_nl80211_scan_get_ssid_info(wn_nl80211_ctx *ctx, const char *iface,
    int (*func)(struct nl_msg *, void *), void *arg)
{
    int err;

    uint32_t iface_id;
    struct nl_cb *cb_ptr;
    struct nl_msg *req_msg;
    
    err = 0;
        
    if (!(iface_id = if_nametoindex(iface))) // 0 return on error
    	goto ERR_EXIT;
    
    if (!(req_msg = nlmsg_alloc()))
        goto ERR_EXIT;
    
    if (!(cb_ptr = nl_cb_alloc(NL_CB_DEFAULT)))
        goto ERR_EXIT_NL_MSG;
    
    /* 
      genlmsg_put
        msg	Netlink message object
        port	Netlink port or NL_AUTO_PORT
        seq	Sequence number of message or NL_AUTO_SEQ
        family	Numeric family identifier
        hdrlen	Length of user header
        flags	Additional Netlink message flags (optional)
        cmd	Numeric command identifier
        version	Interface version 
    */
    
    /*
     *  NLM_F_ROOT - Return based on root of tree. (attr root)
     */
    if (!genlmsg_put(req_msg, 0, 0, (*ctx).nl80211_family_id, 0, NLM_F_DUMP/*(.?)*/, 
        NL80211_CMD_GET_SCAN, 0))
    {    
        fprintf(stderr, "\n%d, genlmsg_put: %d (%s)",__LINE__, err, "failed");
        goto ERR_EXIT_CB_PTR;
    }
    
    if ((err = nla_put_u32(req_msg, NL80211_ATTR_IFINDEX, iface_id)))
    {
        fprintf(stderr, "\n%d, nla_put_u32: %d (%s)", __LINE__, err,
            nl_geterror(-err));
        goto ERR_EXIT_CB_PTR;
    }

    if ((err = nl_cb_set(cb_ptr, NL_CB_VALID, NL_CB_CUSTOM, func, arg)))
    {
        fprintf(stderr, "\n%d, nl_cb_set: %d (%s)",__LINE__, err, 
            nl_geterror(-err));
        goto ERR_EXIT_CB_PTR;
    }
    
    if ((err = nl_cb_set(cb_ptr, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, 
	    wn_p_nl80211_scan_callback_seq_check_noop, NULL)))
    {
	    goto ERR_EXIT_CB_PTR;
    }
    
    if ((err = nl_socket_add_membership(ctx->sock, ctx->grp_id.scan))) 
    {
        fprintf(stderr, "\n%d, nl_socket_add_membership: %d (%s)",__LINE__, err, 
            nl_geterror(-err));
        goto ERR_EXIT_CB_PTR;
    }
    
    // send request, do not need wait ack for this request (cmd) (why.?)
    err = nl_send_auto(ctx->sock, req_msg); // .
    req_msg = NULL; // see http://www.infradead.org/~tgr/libnl/doc/api/nl_8c_source.html#l00469,
                    // nl_send_sync does free the message after send it
    if (err < 0) 
    {
        fprintf(stderr, "\n%d, nl_cb_set: %d (%s)", __LINE__, err, 
            nl_geterror(-err));
        goto ERR_EXIT_SCAN_MEMBERSHIP;
    }
    
    // receive response (multipart)
    fprintf(stderr , "\n%d calling %s", __LINE__, __PRETTY_FUNCTION__);
    if ((err = nl_recvmsgs(ctx->sock, cb_ptr)))
        goto ERR_EXIT_SCAN_MEMBERSHIP;
    
    nl_socket_drop_membership(ctx->sock, ctx->grp_id.scan);
    nl_cb_put(cb_ptr);

    return 0;

ERR_EXIT_SCAN_MEMBERSHIP:
    nl_socket_drop_membership(ctx->sock, ctx->grp_id.scan);
ERR_EXIT_CB_PTR:
    nl_cb_put(cb_ptr);
ERR_EXIT_NL_MSG:
    if (req_msg) nlmsg_free(req_msg);
ERR_EXIT:
    return -1;
}

#define BSSID_MAXHEX_STRLEN 17

// will unblock after NLMSG_DONE is reached (in multipart response)
// (all messages are skipped and on the last, default handler will return NL_STOP)
inline static int 
    print_sta_info(struct nl_msg *msg, void *data)
{
    wn_nl80211_sta_info_node node;
    wn_nl80211_sta_info_node_init_from_nl_msg(&node, msg);
    
    fprintf(stdout, "\n%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx" 
           " %d %u", node.bssid[0], node.bssid[1], node.bssid[2], node.bssid[3],
           node.bssid[4], node.bssid[5], node.rssi_100dBm, node.frequency_MHz);   
           
    wn_nl80211_sta_info_node_free(&node);   
    
    return NL_OK; // call transfers the ownership of 
                                           // the node to callback; should return NL_*(STOP..SKIP, etc)
                                          // it doesn't matter NL_OK or NL_SKIP since it would be the // last hook called (lowest prio) 
}

int main (int arg_n, const char *(args[]))
{
    wn_nl80211_ctx wn_ctx;
    wn_nl80211_scan_param_t param;
       
    if (arg_n < 2)
        return -1;
       
    const char *iface = args[1];
    
    if (wn_nl80211_ctx_init(&wn_ctx))
        goto ERR_EXIT;

    if (wn_nl80211_scan_param_init(&param))
        goto ERR_EXIT_WN_NL80211_CTX;
    
   // wn_nl80211_scan_param_add_ssid_str(&param, "Redmi");// (const unsigned char *)"", 0); // broadcasting probe
    //wn_nl80211_scan_param_add_frequency(&param, 2500);
    if (wn_nl80211_scan_perform(&wn_ctx, iface, &param))
	    goto ERR_EXIT_WN_NL80211_SCAN_PARAM;
    
    if (wn_nl80211_scan_get_ssid_info(&wn_ctx, iface, print_sta_info, NULL))
        goto ERR_EXIT_WN_NL80211_SCAN_PARAM;
    
    wn_nl80211_scan_param_free(&param);
    wn_nl80211_ctx_free(&wn_ctx);
    return 0;
ERR_EXIT_WN_NL80211_SCAN_PARAM:
    wn_nl80211_scan_param_free(&param);
ERR_EXIT_WN_NL80211_CTX:
    wn_nl80211_ctx_free(&wn_ctx);
ERR_EXIT:
    fprintf(stderr , "\n\nERROR\n");
    return -1;
}
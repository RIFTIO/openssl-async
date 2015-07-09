#include "ssl_locl.h"
#include <stdio.h>

struct transmission_queue_node {
    SSL3_TRANSMISSION trans;
    struct transmission_queue_node *prev, *next;
};
struct ssl3_transmission_pool_st {
    struct transmission_queue_node pool[64]; /* Arbitrary */
    struct transmission_queue_node *free_head, *free_tail; /* list of free
                                                            * trans */
    struct transmission_queue_node *head, *tail; /* list of trans inflight to
                                                  * crypto */
    struct transmission_queue_node *skt_head, *skt_tail; /* list of trans
                                                          * waiting to be
                                                          * written to socket */
    /*
     * Points at the top-most free trans. Eventually reaches the top, at
     * which point everything is goverened by free_head and free_tail
     */
    unsigned int pool_break;
    /* A flag indicating that this pool is being post_processed */
    int postprocessing;
};

int ssl3_asynch_push_callback(SSL3_TRANSMISSION * trans,
                              int (*cb) (SSL3_TRANSMISSION * trans,
                                         int status))
{
    OPENSSL_assert(trans->callback_list_top < 10);

    SSL3_ASYNCH_CALLBACK_LIST *p =
        &(trans->callback_list[trans->callback_list_top]);
    p->cb = cb;
    p->cb_data = trans;
    if (trans->callback_list_top > 0)
        p->next = &(trans->callback_list[trans->callback_list_top - 1]);
    else
        p->next = NULL;
    trans->callback_list_top++;
    return 1;
}

void ssl3_remove_last_transmission(SSL *s, int mode)
{
    if (!s || !s->s3)
        return;
    SSL3_TRANSMISSION_POOL *pool = s->s3->transmission_pool;
    struct transmission_queue_node *tail;
    if (!pool)
        return;

    if (ssl3_lock(s, S3_POOL_LOCK) != 0)
        return;
    tail = pool->tail;
    if (ssl3_unlock(s, S3_POOL_LOCK) != 0)
        return;

    if (tail) {
        SSL3_TRANSMISSION *trans = &tail->trans;
        if (!trans)
            return;
        if (SSL_WRITING == mode)
            ssl3_release_buffer(trans->s, &trans->buf,
                                ! !(trans->flags & SSL3_TRANS_FLAGS_SEND));
        ssl3_release_transmission(trans);
    }
}

static int ssl3_process_transmissions(SSL *s, int status)
{
    SSL3_TRANSMISSION_POOL *pool = s->s3->transmission_pool;
    int iterate = 0;

    ssl3_lock(s, S3_POSTPROCESSING_POOL_LOCK);
    if (!pool->postprocessing) {
        iterate = 1;
        pool->postprocessing = 1;
    }
    ssl3_unlock(s, S3_POSTPROCESSING_POOL_LOCK);
    while (iterate) {
        struct transmission_queue_node *head;
        ssl3_lock(s, S3_POSTPROCESSING_POOL_LOCK);
        head = pool->head;
        if (head && head->trans.post) {
            SSL3_TRANSMISSION *trans = &head->trans;
            ssl3_unlock(s, S3_POSTPROCESSING_POOL_LOCK);
 
            if (status < 0) {
                if (trans->s->asynch_completion_callback) {
                    if (trans->flags & SSL3_TRANS_FLAGS_SEND)
                        return trans->s->asynch_completion_callback(1, status,
                                                                    NULL, 0,
                                                                    NULL,
                                                                    trans->
                                                                    s->asynch_completion_callback_arg);
                    else
                        return trans->s->asynch_completion_callback(0, status,
                                                                    NULL, 0,
                                                                    NULL,
                                                                    trans->
                                                                    s->asynch_completion_callback_arg);
                }
            } else if (trans->s->asynch_completion_callback) {
                if (trans->flags & SSL3_TRANS_FLAGS_SEND) {
                    trans->s->asynch_completion_callback(1, status,
                                                         trans->orig,
                                                         trans->origlen,
                                                         trans->s,
                                                         trans->
                                                         s->asynch_completion_callback_arg);
                } else
                    trans->s->asynch_completion_callback(0, status,
                                                         trans->rec.data,
                                                         trans->rec.length,
                                                         trans->s,
                                                         trans->
                                                         s->asynch_completion_callback_arg);
            }

            while (trans->post && trans->callback_list_top > 0) {
                SSL3_ASYNCH_CALLBACK_LIST *p =
                    &(trans->callback_list[--trans->callback_list_top]);
                status = p->cb(trans, status);
            }

            /*
             * If trans->post is false, something extraordinary
             * happened that has us push the rest of the processing
             * to a later time.  For example, if one of the
             * callbacks initiates another crypto or digest
             * operation on the same transmissions.
             */
            ssl3_lock(s, S3_POSTPROCESSING_POOL_LOCK);
            if (!trans->post) {
                pool->postprocessing = 0;
                ssl3_unlock(s, S3_POSTPROCESSING_POOL_LOCK);
                break;
            }
            ssl3_unlock(s, S3_POSTPROCESSING_POOL_LOCK);


#ifndef DISABLE_ASYNCH_BULK_PERF
            if (status > 0)
#endif
            {
                /*
                 * Only free transmission buffers if callback was successful
                 * (i.e. data successfully sent to socket)
                 */

                if ((trans->s->asynch_completion_callback) &&
                    (trans->flags & SSL3_TRANS_FLAGS_SEND) && (trans->orig)) {
                    OPENSSL_free(trans->orig);
                }
                ssl3_release_buffer(trans->s, &trans->buf,
                                    ! !(trans->flags &
                                        SSL3_TRANS_FLAGS_SEND));
                ssl3_release_transmission(trans);
            }
        } else {
            pool->postprocessing = 0;
            ssl3_unlock(s, S3_POSTPROCESSING_POOL_LOCK);
            break;
        }
    }
    return status;
}

int ssl3_asynch_handle_cipher_callbacks(unsigned char *data, int datalen,
                                        void *userdata, int status)
{
#ifdef ASYNCH_DEBUG
    fprintf(stderr,
            "ssl3_asynch_handle_cipher_callbacks: data = %p, datalen = %d, userdata = %p, status = %d\n",
            data, datalen, userdata, status);
#endif
    if (NULL == userdata) {
        return status;
    }

    if (data == NULL) {
        /*
         * We have been called because the cipher was initiated. Do nothing
         * with this, as the updates are done elsewhere
         */
    } else {
        SSL3_TRANSMISSION *trans = (SSL3_TRANSMISSION *) userdata;

        trans->rec.off = 0;
        trans->rec.length = datalen;
        trans->post = 1;

        status = ssl3_process_transmissions(trans->s, status);
    }
    return status;
}

int ssl3_asynch_handle_digest_callbacks(unsigned char *md, unsigned int size,
                                        void *userdata, int status)
{
#ifdef ASYNCH_DEBUG
    fprintf(stderr,
            "ssl3_asynch_handle_digest_callbacks: md = %p, size = %d, userdata = %p, status = %d\n",
            md, size, userdata, status);
#endif
    if (NULL == userdata) {
        return status;
    }
    if (status < 0) {
        SSL3_TRANSMISSION *trans = (SSL3_TRANSMISSION *) userdata;

        if (trans->s->asynch_completion_callback) {
            if (trans->flags & SSL3_TRANS_FLAGS_SEND)
                return trans->s->asynch_completion_callback(1, status, NULL,
                                                            0, NULL,
                                                            trans->
                                                            s->asynch_completion_callback_arg);
            else
                return trans->s->asynch_completion_callback(0, status, NULL,
                                                            0, NULL,
                                                            trans->
                                                            s->asynch_completion_callback_arg);
        } else
            SSLerr(SSL_F_SSL3_ASYNCH_HANDLE_DIGEST_CALLBACKS,
                   SSL_R_ASYNCH_COMPL_CALLBACK_NOT_DEFINED);
        return status;
    }

    if (md == NULL) {
        /*
         * We have been called because the digest was initiated or updated.
         * Do nothing with this, as the final is done elsewhere
         */
    } else {
        SSL3_TRANSMISSION *trans = (SSL3_TRANSMISSION *) userdata;

        trans->post = 1;

        status = ssl3_process_transmissions(trans->s, status);
    }
    return status;
}

SSL3_TRANSMISSION *ssl3_get_transmission_before(SSL *s, SSL3_TRANSMISSION * t)
{
    struct transmission_queue_node *tqn = NULL;
    SSL3_TRANSMISSION_POOL *p = s->s3->transmission_pool;
    struct transmission_queue_node *ttqn =
        (struct transmission_queue_node *)t;

    if (ssl3_lock(s, S3_POOL_LOCK) != 0)
        return NULL;

    if (!p) {
        p = (SSL3_TRANSMISSION_POOL *)
            OPENSSL_malloc(sizeof(SSL3_TRANSMISSION_POOL));
        if (!p) {
#ifdef ASYNCH_DEBUG
            fprintf(stderr, "OPENSSL_malloc failed to get memory\n");
#endif
            ssl3_unlock(s, S3_POOL_LOCK);
            return NULL;
        }
        p->head = p->tail = p->free_head = p->free_tail = p->skt_head =
            p->skt_tail = (void *)0;
        p->pool_break = 0;
        p->postprocessing = 0;
        s->s3->transmission_pool = p;
    }

    if (p->free_head && p->free_tail) {
        tqn = p->free_head;
        p->free_head = tqn->next;
        if (p->free_head == NULL)
            p->free_tail = NULL;
    } else if (p->pool_break < sizeof(p->pool) / sizeof(p->pool[0])) {
        tqn = &(p->pool[p->pool_break++]);
    }
    if (ssl3_unlock(s, S3_POOL_LOCK) != 0)
        return NULL;

    if (!tqn)
        return NULL;

    tqn->trans.post = 0;
    memset(&tqn->trans, 0, sizeof(tqn->trans));
    tqn->trans.s = s;

    if (ssl3_lock(s, S3_POOL_LOCK) != 0)
        return NULL;
    if (ttqn) {
        tqn->next = ttqn;
        tqn->prev = ttqn->prev;
        ttqn->prev = tqn;
        if (!tqn->prev)
            p->head = tqn;
        else
            tqn->prev->next = tqn;
    } else {
        tqn->next = NULL;
        tqn->prev = p->tail;
        if (p->tail != NULL)
            p->tail->next = tqn;
        p->tail = tqn;
        if (p->head == NULL)
            p->head = tqn;
    }
    if (ssl3_unlock(s, S3_POOL_LOCK) != 0)
        return NULL;

    return &tqn->trans;
}

SSL3_TRANSMISSION *ssl3_get_transmission(SSL *s)
{
    return ssl3_get_transmission_before(s, NULL);
}

void ssl3_release_transmission(SSL3_TRANSMISSION * trans)
{
    /*
     * This works because we know that SSL3_TRANSMISSION is at the start of
     * struct transmission_queue_node
     */
    struct transmission_queue_node *tqn =
        (struct transmission_queue_node *)trans;
    SSL3_TRANSMISSION_POOL *p = trans->s->s3->transmission_pool;
    OPENSSL_assert(tqn >= &(p->pool[0])
                   && tqn < &(p->pool[p->pool_break]));

    if (ssl3_lock(trans->s, S3_POOL_LOCK) != 0)
        return;
    if (tqn->next == NULL)
        p->tail = tqn->prev;
    else
        tqn->next->prev = tqn->prev;
    if (tqn->prev == NULL)
        p->head = tqn->next;
    else
        tqn->prev->next = tqn->next;
    trans->callback_list_top = 0;
    tqn->next = NULL;
    tqn->prev = p->free_tail;
    if (p->free_tail != NULL)
        p->free_tail->next = tqn;
    p->free_tail = tqn;
    if (p->free_head == NULL)
        p->free_head = tqn;
    ssl3_unlock(trans->s, S3_POOL_LOCK);
}

/*
 * This function returns a transmission from the socket list
 * (skt_head,skt_tail) to the free transmission list (free_head,free_tail)
 */
void ssl3_release_transmission_skt(SSL3_TRANSMISSION * trans)
{
    /*
     * This works because we know that SSL3_TRANSMISSION is at the start of
     * struct transmission_queue_node
     */
    struct transmission_queue_node *tqn =
        (struct transmission_queue_node *)trans;
    SSL3_TRANSMISSION_POOL *p = trans->s->s3->transmission_pool;
    OPENSSL_assert(tqn >= &(p->pool[0])
                   && tqn < &(p->pool[p->pool_break]));

    if (tqn->next == NULL)
        p->skt_tail = tqn->prev;
    else
        tqn->next->prev = tqn->prev;
    if (tqn->prev == NULL)
        p->skt_head = tqn->next;
    else
        tqn->prev->next = tqn->next;

    tqn->next = NULL;
    tqn->prev = p->free_tail;
    if (p->free_tail != NULL)
        p->free_tail->next = tqn;
    p->free_tail = tqn;
    if (p->free_head == NULL)
        p->free_head = tqn;
}

void ssl3_cleanup_transmission_pool(SSL *s)
{
    struct transmission_queue_node *pnode = NULL;
    if (s->s3->transmission_pool) {
        pnode = s->s3->transmission_pool->head;
        s->s3->transmission_pool->head = NULL;
        while(pnode) {
            if(pnode->trans.buf.buf) {
                CRYPTO_free(pnode->trans.buf.buf);
                pnode->trans.buf.buf = NULL;
            }
            pnode = pnode->next;
        }
        OPENSSL_cleanse(s->s3->transmission_pool,
                        sizeof *s->s3->transmission_pool);
        OPENSSL_free(s->s3->transmission_pool);
    }
}

/* Reading records */
struct read_record_queue_node {
    SSL3_READ_RECORD rec;
    int extracted;
    struct read_record_queue_node *prev, *next;
};
struct ssl3_read_record_pool_st {
    struct read_record_queue_node pool[100]; /* Arbitrary */
    struct read_record_queue_node *head, *tail, *free_head, *free_tail;
    /*
     * Points at the top-most free record. Eventually reaches the top, at
     * which point everything is goverened by free_head and free_tail
     */
    unsigned int pool_break;
};
int ssl3_get_record_asynch_cb(SSL3_TRANSMISSION * trans, int status)
{
    struct read_record_queue_node *rrqn = NULL;
    SSL3_READ_RECORD_POOL *p = trans->s->s3->read_record_pool;

    OPENSSL_assert(trans != NULL);

    if (ssl3_lock(trans->s, S3_POOL_LOCK) != 0)
        return 0;
    if (!p) {
        p = (SSL3_READ_RECORD_POOL *)
            OPENSSL_malloc(sizeof(SSL3_READ_RECORD_POOL));
        if (!p) {
#ifdef ASYNCH_DEBUG
            fprintf(stderr, "OPENSSL_malloc failed to get memory\n");
#endif
            ssl3_unlock(trans->s, S3_POOL_LOCK);
            return 0;
        }
        memset(p, 0, sizeof(SSL3_READ_RECORD_POOL));
        trans->s->s3->read_record_pool = p;
    }

    if (p) {
        if (p->free_head && p->free_tail) {
            rrqn = p->free_head;
            p->free_head = rrqn->next;
            if (p->free_head == NULL)
                p->free_tail = NULL;
        } else if (p->pool_break < sizeof(p->pool) / sizeof(p->pool[0])) {
            rrqn = &(p->pool[p->pool_break++]);
        }
    }
    if (ssl3_unlock(trans->s, S3_POOL_LOCK) != 0)
        return 0;

    if (!rrqn)
        return 0;

    rrqn->extracted = 0;
    memcpy(&rrqn->rec.rec, &trans->rec, sizeof(SSL3_RECORD));
    memcpy(&rrqn->rec.buf, &trans->buf, sizeof(SSL3_BUFFER));
    rrqn->rec.packet = trans->packet;
    rrqn->rec.packet_length = trans->packet_length;
    rrqn->rec.origlen = trans->origlen;
    memcpy(rrqn->rec.md, trans->_md, EVP_MAX_MD_SIZE);
    rrqn->rec.mac = trans->mac;
    rrqn->rec.mac_size = trans->mac_size;
    memset(&trans->rec, 0, sizeof(SSL3_RECORD));
    memset(&trans->buf, 0, sizeof(SSL3_BUFFER));

    rrqn->rec.status = status;
    rrqn->rec.s = trans->s;

    if (ssl3_lock(trans->s, S3_POOL_LOCK) != 0)
        return 0;
    ssl_atomic_dec(trans->s->s3->outstanding_read_crypto);

    rrqn->next = NULL;
    rrqn->prev = p->tail;
    if (p->tail != NULL)
        p->tail->next = rrqn;
    p->tail = rrqn;
    if (p->head == NULL)
        p->head = rrqn;

    OPENSSL_assert(rrqn != NULL);
    if (ssl3_unlock(trans->s, S3_POOL_LOCK) != 0)
        return 0;

    return 1;
}

SSL3_READ_RECORD *ssl3_extract_read_record(const SSL *s)
{
    struct read_record_queue_node *rrqn;
    SSL3_READ_RECORD_POOL *p = s->s3->read_record_pool;

    if (p == NULL)
        return NULL;

    if (ssl3_lock((SSL *)s, S3_POOL_LOCK) != 0)
        return NULL;
    rrqn = p->head;
    if (rrqn) {
        if (rrqn->next == NULL)
            p->tail = rrqn->prev;
        else
            rrqn->next->prev = rrqn->prev;
        if (rrqn->prev == NULL)
            p->head = rrqn->next;
        else
            rrqn->prev->next = rrqn->next;

        rrqn->prev = NULL;
        rrqn->next = NULL;
    }
    if (ssl3_unlock((SSL *)s, S3_POOL_LOCK) != 0)
        return NULL;

    if (rrqn == NULL)
        return NULL;

    rrqn->extracted = 1;
    return &rrqn->rec;
}

void ssl3_release_read_record(SSL3_READ_RECORD * rec)
{
    /*
     * This works because we know that SSL3_READ_RECORD is at the start of
     * struct read_record_queue_node
     */
    struct read_record_queue_node *rrqn =
        (struct read_record_queue_node *)rec;
    SSL3_READ_RECORD_POOL *p = rec->s->s3->read_record_pool;

    OPENSSL_assert(rrqn->extracted && rrqn >= &(p->pool[0])
                   && rrqn < &(p->pool[p->pool_break]));
    if (ssl3_lock(rec->s, S3_POOL_LOCK) != 0)
        return;
    rrqn->prev = p->free_tail;
    if (p->free_tail != NULL)
        p->free_tail->next = rrqn;
    p->free_tail = rrqn;
    if (p->free_head == NULL)
        p->free_head = rrqn;
    ssl3_unlock(rec->s, S3_POOL_LOCK);
}

void ssl3_cleanup_read_record_pool(SSL *s)
{
    SSL3_READ_RECORD *arr=NULL;
    if (s->s3->read_record_pool) {
        while((arr = ssl3_extract_read_record(s)) != NULL) {
            if(arr->buf.buf) {
                CRYPTO_free(arr->buf.buf);
                arr->buf.buf = NULL;
            }
        }
        OPENSSL_cleanse(s->s3->read_record_pool,
                        sizeof *s->s3->read_record_pool);
        OPENSSL_free(s->s3->read_record_pool);
    }
}

/*
 * This function checks the queue of transmissions waiting for submission to
 * socket. Starting at the head of the socket transmission queue this
 * function starts sending data to the write socket. If the data is
 * successfully sent the transmission buffers are free-ed and the next
 * transmission at the head of the socket transmission queue is processed.
 * This function returns greater than 0 in case of success. If data is not
 * successfully sent (e.g. due to write socket becoming full) this function
 * sets the ssl rwstate to WRITING and returns less than 0 to indicate that
 * further progress cannot be made until write socket has more space.
 */
int ssl3_asynch_send_skt_queued_data(SSL *s)
{
    SSL3_TRANSMISSION_POOL *p = NULL;
    struct transmission_queue_node *tqn = NULL;
    SSL3_TRANSMISSION *trans = NULL;
    SSL3_BUFFER *wb = NULL;
    int i = 0;

    p = s->s3->transmission_pool;
    if (p == NULL) {
        return 1;
    }

    tqn = p->skt_head;

    while (tqn != NULL) {
        trans = &(tqn->trans);
        if (trans->dsw_ef_buf.buf)
            wb = &trans->dsw_ef_buf;
        else
            wb = &trans->buf;
        for (;;) {
            clear_sys_error();
            if (s->wbio != NULL) {
                s->rwstate = SSL_WRITING;
                i = BIO_write(s->wbio,
                              (char *)&(wb->buf[wb->offset]),
                              (unsigned int)wb->left);
            } else {
                SSLerr(SSL_F_SSL3_ASYNCH_SEND_SKT_QUEUED_DATA,
                       SSL_R_BIO_NOT_SET);
                return -1;
            }
            if (i == wb->left) {
                if (trans->dsw_ef_buf.buf) {
                    ssl3_release_buffer(trans->s, &trans->dsw_ef_buf,
                                        ! !(trans->flags &
                                            SSL3_TRANS_FLAGS_SEND));
                    memset(&trans->dsw_ef_buf, 0, sizeof(SSL3_BUFFER));
                    wb = &trans->buf;
                    continue;
                }
                wb->left = 0;
                wb->offset += i;
                s->rwstate = SSL_NOTHING;
                tqn = tqn->next; /* Next trans to send */

                ssl3_release_buffer(trans->s, &trans->buf,
                                    ! !(trans->flags &
                                        SSL3_TRANS_FLAGS_SEND));
                ssl3_release_transmission_skt(trans);
                (void)BIO_flush(s->wbio);
                ssl_atomic_dec(s->s3->outstanding_write_records);
                BIO_clear_retry_flags(s->wbio);
                break;          /* break for() */
            } else if (i <= 0) {
                /* Made no progress return an error */
                if (!BIO_should_retry(s->wbio)) {
                    ssl3_set_conn_status(s, i);
                    if (trans->dsw_ef_buf.buf) {
                        ssl3_release_buffer(trans->s, &trans->dsw_ef_buf,
                                            ! !(trans->flags &
                                                SSL3_TRANS_FLAGS_SEND));
                        memset(&trans->dsw_ef_buf, 0, sizeof(SSL3_BUFFER));
                    }
                    tqn = tqn->next;
                    ssl_atomic_dec(s->s3->outstanding_write_records);

                    ssl3_release_buffer(trans->s, &trans->buf,
                                        ! !(trans->flags &
                                            SSL3_TRANS_FLAGS_SEND));
                    ssl3_release_transmission_skt(trans);
                    break;
                } else
                    return (i);
            } else {            /* i > 0 */

                /* Made some progress */
                wb->offset += i;
                wb->left -= i;
            }
        }
    }
    return i;
}

/*
 * This function queues transmissions for submission to socket at a later
 * time
 */
void ssl3_asynch_queue_write_socket_trans(SSL *s)
{
    SSL3_TRANSMISSION_POOL *p = NULL;
    struct transmission_queue_node *tqn = NULL;

    p = s->s3->transmission_pool;
    tqn = p->head;

    p->head = tqn->next;
    if (tqn->next != NULL)
        tqn->next->prev = tqn->prev;
    else
        p->tail = tqn->prev;

    if (p->skt_head == NULL) {
        /* First trans in socket queue */
        p->skt_head = tqn;
        p->skt_tail = tqn;
        tqn->next = NULL;
        tqn->prev = NULL;
    } else {
        /* Add to tail of list */
        p->skt_tail->next = tqn;
        tqn->next = NULL;
        tqn->prev = p->skt_tail;
        p->skt_tail = tqn;
    }
}

/*
 * This function checks if there is transmissions already queued waiting to
 * be written out to the socket. If there is no transmissions queued for the
 * socket this function returns 0. If there are transmissions queued for the
 * socket this function adds the current transmission to this queue and
 * returns 1
 */
int ssl3_asynch_check_write_socket_trans(SSL *s)
{
    SSL3_TRANSMISSION_POOL *p = NULL;

    p = s->s3->transmission_pool;
    if (p == NULL) {
        return 0;
    }

    if (p->skt_head != NULL) {
        ssl3_asynch_queue_write_socket_trans(s);
        return 1;
    } else {
        return 0;
    }
}

void ssl3_set_conn_status(SSL *s, int status)
{
    s->conn_status = status;
}

int ssl3_get_conn_status(SSL *s)
{
    return s->conn_status;
}

#include <string.h>
#include <engine/eng_int.h>

int ENGINE_set_id(ENGINE *e, const char *id)
{
    return 1;
}

int ENGINE_set_name(ENGINE *e, const char *name)
{
    return 1;
}

int ENGINE_set_destroy_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR destroy_f)
{
    return 1;
}

int ENGINE_set_init_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR init_f)
{
    return 1;
}

int ENGINE_set_finish_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR finish_f)
{
    return 1;
}


int ENGINE_set_ciphers(ENGINE *e, ENGINE_CIPHERS_PTR f)
{
    return 1;
}


#undef OPENSSL_malloc
#define OPENSSL_malloc malloc

#undef OPENSSL_free
#define OPENSSL_free free

ENGINE *ENGINE_new(void)
{
    ENGINE *ret;
    ret = (ENGINE *)OPENSSL_malloc(sizeof(ENGINE));
    if (ret) {
        memset(ret, 0, sizeof(ENGINE));
        ret->struct_ref = 1;
    }
    return ret;
}

int ENGINE_free(ENGINE *e)
{
    if (!e)
        return 0;
    
    if(--e->struct_ref > 0)
        return 1;

    if (e->destroy) {
        e->destroy(e);
    }

    OPENSSL_free(e);
    
    return 1;
}

int ENGINE_add(ENGINE *e)
{
    return 1;
}

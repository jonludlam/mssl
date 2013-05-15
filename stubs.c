

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/fail.h>

#include "matrixssl/matrixsslApi.h"

#include "../matrixssl-3-4-2-open/sampleCerts/RSA/ALL_RSA_CAS.h"

/* sslKeys_t custom block */

static struct custom_operations sslKeys_t_ops = {
  "matrixssl.sslKeys_t",
  custom_finalize_default,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default
};

#define sslKeys_t_val(v) (*((sslKeys_t **) Data_custom_val(v)))

static value alloc_sslKeys_t(sslKeys_t *k)
{
  value v = alloc_custom(&sslKeys_t_ops, sizeof(sslKeys_t *), 0, 1);
  sslKeys_t_val(v) = k;
  return v;
}


/* sslSessionId_t custom block */

static struct custom_operations sslSessionId_t_ops = {
  "matrixssl.sslSessionId_t",
  custom_finalize_default,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default
};

#define sslSessionId_t_val(v) (*((sslSessionId_t **) Data_custom_val(v)))

static value alloc_sslSessionId_t(sslSessionId_t *s)
{
  value v = alloc_custom(&sslSessionId_t_ops, sizeof(sslSessionId_t *), 0, 1);
  sslSessionId_t_val(v) = s;
  return v;
}

/* ssl_t custom block */

static struct custom_operations ssl_t_ops = {
  "matrixssl.ssl_t",
  custom_finalize_default,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default
};

#define ssl_t_val(v) (*((ssl_t **) Data_custom_val(v)))

static value alloc_ssl_t(ssl_t *s)
{
  value v = alloc_custom(&ssl_t_ops, sizeof(ssl_t *), 0, 1);
  ssl_t_val(v) = s;
  return v;
}


CAMLprim value stub_core_open(value unit)
{
  CAMLparam1(unit);
  int result = matrixSslOpen();
  CAMLreturn(Val_int(result));
}

CAMLprim value stub_core_close(value unit)
{
  CAMLparam1(unit);
  matrixSslClose();
  CAMLreturn(Val_unit);
}


CAMLprim value stub_new_keys(value unit)
{
  CAMLparam1 (unit);
  sslKeys_t *keys;

  if(matrixSslNewKeys(&keys) < 0) {
    caml_failwith("Failed to allocate memory for keys");
  }

  CAMLreturn(alloc_sslKeys_t(keys));
}

CAMLprim value stub_delete_keys(value keys)
{
  CAMLparam1(keys);

  sslKeys_t *k = sslKeys_t_val(keys);
  matrixSslDeleteKeys(k);

  CAMLreturn(Val_unit);
}

CAMLprim value stub_load_rsa_keys_mem(value keys, value cert, value priv, value trustedCA)
{
  CAMLparam4(keys,cert,priv,trustedCA);

  int cert_len = caml_string_length(cert);
  int priv_len = caml_string_length(priv);
  int trustedCA_len = caml_string_length(trustedCA);

  unsigned char *c_cert=NULL;
  unsigned char *c_priv=NULL;
  unsigned char *c_trustedCA=NULL;

  if(cert_len > 0) {
    c_cert = (unsigned char *)malloc(cert_len);
    if(!c_cert)
      caml_failwith("Failed to alloc memory");
    memcpy(c_cert,String_val(cert),cert_len);
  }

  if(priv_len > 0) {
    c_priv = (unsigned char *)malloc(priv_len);
    if(!c_priv)
      caml_failwith("Failed to alloc memory");
    memcpy(c_priv,String_val(priv),priv_len);
  }

  if(trustedCA_len > 0) {
    c_trustedCA = (unsigned char *)malloc(trustedCA_len);
    if(!c_trustedCA)
      caml_failwith("Failed to alloc memory");
    memcpy(c_trustedCA,String_val(trustedCA),trustedCA_len);
  }

  fprintf(stderr,"Got lens: %d %d %d\n",cert_len,priv_len,trustedCA_len);

  int rc;

  rc=matrixSslLoadRsaKeysMem(sslKeys_t_val(keys), c_cert, cert_len, c_priv, priv_len,
			     c_trustedCA, trustedCA_len);

  if(rc<0) {
    fprintf(stderr,"rc=%d\n",rc);
    caml_failwith("Failed to load certificates");
  }

  CAMLreturn(Val_unit);
}


CAMLprim value stub_load_rsa_keys(value keys, value cert, value priv, value trustedCA)
{
  CAMLparam4(keys,cert,priv,trustedCA);

  unsigned char *c_cert = (unsigned char *)strdup(String_val(cert));
  unsigned char *c_priv = (unsigned char *)strdup(String_val(priv));
  unsigned char *c_trustedCA = (unsigned char *)strdup(String_val(trustedCA));

  int cert_len = caml_string_length(cert);
  int priv_len = caml_string_length(priv);
  int trustedCA_len = caml_string_length(trustedCA);

  fprintf(stderr,"Got lens: %d %d %d\n",cert_len,priv_len,trustedCA_len);

  if(cert_len==0) c_cert=NULL;
  if(priv_len==0) c_priv=NULL;
  if(trustedCA_len==0) c_trustedCA=NULL;

  int rc;

  rc=matrixSslLoadRsaKeysMem(sslKeys_t_val(keys), c_cert, cert_len, c_priv, priv_len,
			     c_trustedCA, trustedCA_len);

  if(rc<0) {
    fprintf(stderr,"rc=%d\n",rc);
    caml_failwith("Failed to load certificates");
  }

  CAMLreturn(Val_unit);
}

CAMLprim value stub_new_session_id(value unit)
{
  CAMLparam1 (unit);
  sslSessionId_t *s;

  if(matrixSslNewSessionId(&s) < 0) {
    caml_failwith("Failed to allocate memory for session");
  }

  CAMLreturn(alloc_sslSessionId_t(s));
}

CAMLprim value stub_clear_session_id(value s)
{
  CAMLparam1(s);

  matrixSslClearSessionId(sslSessionId_t_val(s));

  CAMLreturn(Val_unit);
}

CAMLprim value stub_delete_session_id(value s)
{
  CAMLparam1(s);

  matrixSslDeleteSessionId(sslSessionId_t_val(s));

  CAMLreturn(Val_unit);
}

static int32 certCb(ssl_t *ssl, psX509Cert_t *cert, int32 alert)
{
			return SSL_ALLOW_ANON_CONNECTION;
  return PS_SUCCESS;
}

CAMLprim value stub_new_client_session_native(value keys, value sid, value cipherSpec,
					   value cert_cb, value extensions, value ext_cb,
					   value flags)
{
  CAMLparam5(keys, sid, cipherSpec, cert_cb, extensions);
  CAMLxparam2(ext_cb, flags);

  ssl_t *ssl;
  int rc;

  rc=matrixSslNewClientSession(&ssl, sslKeys_t_val(keys), NULL, /*sslSessionId_t_val(sid), */
			       Int_val(cipherSpec), certCb, NULL, NULL, 0);

  if(rc != MATRIXSSL_REQUEST_SEND) {
    fprintf(stderr,"rc=%d\n",rc);
    caml_failwith("New client session failed");

  }

  CAMLreturn(alloc_ssl_t(ssl));  
}

CAMLprim value stub_new_client_session_bc(value *argv, int argn)
{
  return stub_new_client_session_native(argv[0],argv[1],argv[2],
					argv[3],argv[4],argv[5],
					argv[6]);

}

CAMLprim value stub_get_out_data(value ssl)
{
  CAMLparam1(ssl);
  CAMLlocal1(v);
  unsigned char *str;

  int rc=matrixSslGetOutdata(ssl_t_val(ssl), &str);

  if(rc>0) {
    v=caml_alloc_string(rc);
    memcpy(String_val(v),str,rc);
  } else {
    caml_failwith("No data");
  }

  CAMLreturn(v);
}

value get_return_code(int rc, unsigned char *ptr, int len)
{
  CAMLparam0();
  CAMLlocal2(ret,str);

  switch(rc) {
  case PS_SUCCESS:
    printf("XX PS_SUCCESS\n");
    ret=Val_int(0);
    break;
  case MATRIXSSL_REQUEST_SEND:
    printf("XX PS_REQUEST_SEND\n");
    ret=Val_int(1);
    break;
  case MATRIXSSL_REQUEST_RECV:
    printf("XX PS_REQUEST_RECV\n");
    ret=Val_int(2);
    break;
  case MATRIXSSL_HANDSHAKE_COMPLETE:
    ret=Val_int(3);
    break;
  case MATRIXSSL_RECEIVED_ALERT:
    ret=caml_alloc(2,0);
    Store_field(ret,0,Val_int((unsigned int)ptr[0]));
    Store_field(ret,1,Val_int((unsigned int)ptr[1]));
    break;
  case MATRIXSSL_APP_DATA:
    ret=caml_alloc(1,1);
    str=caml_alloc_string(len);
    memcpy(String_val(str),ptr,len);
    Store_field(ret,0,str);
    break;
  default:
    caml_failwith("Unknown return code!");
  }
    
  CAMLreturn(ret);
}

CAMLprim value stub_sent_data(value ssl, value transferred)
{
  CAMLparam2(ssl,transferred);
  int rc;

  rc=matrixSslSentData(ssl_t_val(ssl), Int_val(transferred));

  if(rc<0) {
    caml_failwith("Sent data");
  }

  CAMLreturn(get_return_code(rc,NULL,0));
}

CAMLprim value stub_received_data(value ssl, value str)
{
  CAMLparam2(ssl,str);
  CAMLlocal1(ret);

  int str_len = caml_string_length(str);
  unsigned char *buf=NULL;
  unsigned int len, to_cpy;
  int rc;
  
  len=matrixSslGetReadbuf(ssl_t_val(ssl), &buf);

  to_cpy = (len<str_len) ? len : str_len;

  memcpy(buf,String_val(str),len);

  rc=matrixSslReceivedData(ssl_t_val(ssl), to_cpy, &buf, &len);

  if(rc<0) {
    caml_failwith("Received Data");
  }

  CAMLreturn(get_return_code(rc,buf,len));
}

CAMLprim value stub_processed_data(value ssl)
{
  CAMLparam1(ssl);
  unsigned char *buf=NULL;
  unsigned int len;
  int rc;

  rc=matrixSslProcessedData(ssl_t_val(ssl), &buf, &len);

  if(rc<0) {
    caml_failwith("Processed Data");
  }

  CAMLreturn(get_return_code(rc,buf,len));
}

CAMLprim value stub_encode_data(value ssl, value str)
{
  CAMLparam2(ssl,str);
  
  unsigned char *buf=NULL;
  int len=0;
  int rc;

  memcpy(buf,String_val(str),len);
  len = caml_string_length(str);
  rc=matrixSslEncodeToOutdata(ssl_t_val(ssl), (unsigned char *)String_val(str), len);

  if(rc<0) {
    caml_failwith("Failed to encode writebuf");
  }

  CAMLreturn(Val_int(rc));
}

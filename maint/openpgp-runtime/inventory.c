/* Standalone v1 public inventory only. HOME is supplied by a trusted launcher,
 * never by a browser/protocol field. No account authority is implemented here. */
#include <gpgme.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifndef INVENTORY_ENGINE
#define INVENTORY_ENGINE "/usr/local/bin/gpg"
#endif
#define LIMIT 65536
static char output[LIMIT], fingerprints[288][65];
static size_t used, seen;
static int append(const char *fmt, ...) {
 va_list ap; va_start(ap,fmt); int n=vsnprintf(output+used,LIMIT-used,fmt,ap);va_end(ap);
 if(n<0||(size_t)n>=LIMIT-used)return 0;used+=(size_t)n;return 1;
}
static int version(const char *s) {
 if(!s||!*s||strlen(s)>64)return 0;
 for(;*s;s++)if(!((*s>='0'&&*s<='9')||*s=='.'||*s=='-'||(*s>='a'&&*s<='z')))return 0;
 return 1;
}
static int fingerprint(const char *s) {
 if(!s||(strlen(s)!=40&&strlen(s)!=64)||seen==288)return 0;
 for(const char *p=s;*p;p++)if(!((*p>='0'&&*p<='9')||(*p>='A'&&*p<='F')))return 0;
 for(size_t i=0;i<seen;i++)if(!strcmp(fingerprints[i],s))return 0;
 strcpy(fingerprints[seen++],s);return 1;
}
static int emit(gpgme_subkey_t k) {
 if(!k||!fingerprint(k->fpr)||k->timestamp<0||k->expires<0)return 0;
 return append("{\"fingerprint\":\"%s\",\"algorithm\":%u,\"bits\":%u,\"created\":%lu,\"expires\":%lu,\"revoked\":%s,\"expired\":%s,\"disabled\":%s,\"invalid\":%s,\"can_sign\":%s,\"can_encrypt\":%s,\"can_certify\":%s,\"can_authenticate\":%s}",k->fpr,(unsigned)k->pubkey_algo,k->length,(unsigned long)k->timestamp,(unsigned long)k->expires,k->revoked?"true":"false",k->expired?"true":"false",k->disabled?"true":"false",k->invalid?"true":"false",k->can_sign?"true":"false",k->can_encrypt?"true":"false",k->can_certify?"true":"false",k->can_authenticate?"true":"false");
}
static int private_file(const char *home,const char *name,int required) {
 char path[4096];struct stat st;int n=snprintf(path,sizeof(path),"%s/%s",home,name);
 if(n<0||(size_t)n>=sizeof(path))return 0;
 if(lstat(path,&st))return !required;
 return S_ISREG(st.st_mode)&&st.st_uid==geteuid()&&!(st.st_mode&0077);
}
static int valid_home(const char *home) {
 struct stat st;char actual[4096];
 if(!home||home[0]!='/'||!realpath(home,actual)||strcmp(home,actual)||lstat(home,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&0777)!=0700)return 0;
 /* This initial adapter supports provisioned local keybox homes only. */
 if(!private_file(home,"pubring.kbx",1)||!private_file(home,"trustdb.gpg",1))return 0;
 for(size_t i=0;i<3;i++){const char *names[]={"gpg.conf","common.conf","gpg-agent.conf"};char path[4096];if(snprintf(path,sizeof(path),"%s/%s",home,names[i])>=(int)sizeof(path)||!lstat(path,&st))return 0;}
 return 1;
}
static gpgme_error_t status_error(void *hook,const char *keyword,const char *args) {
 (void)args;
 if(!strcmp(keyword,"ERROR")||!strcmp(keyword,"FAILURE")||!strcmp(keyword,"TRUNCATED")){*(int *)hook=1;return gpg_error(GPG_ERR_GENERAL);}
 return 0;
}
static int confine(const char *home) {
#ifdef __OpenBSD__
 const char *files[]={INVENTORY_ENGINE,"/usr/local/bin/gpgconf","/usr/libexec/ld.so","/usr/local/lib","/usr/lib","/var/run/ld.so.hints","/etc/localtime","/dev/null","/dev/urandom"};
 const char *perms[]={"rx","rx","rx","r","r","r","r","rw","r"};
 int present[sizeof(files)/sizeof(files[0])];
 for(size_t i=0;i<sizeof(files)/sizeof(files[0]);i++){struct stat st;present[i]=!stat(files[i],&st);}
 if(unveil(home,"r"))return 0;
 for(size_t i=0;i<sizeof(files)/sizeof(files[0]);i++)if(present[i]&&unveil(files[i],perms[i]))return 0;
 if(unveil(NULL,NULL)||pledge("stdio rpath wpath proc exec error","stdio rpath wpath proc exec error"))return 0;
 return 1;
#else
 (void)home;return 0;
#endif
}
int main(int argc,char **argv) {
 gpgme_ctx_t ctx=NULL;gpgme_key_t key=NULL;gpgme_error_t err;int ok=0,status_failed=0;struct rlimit core={0,0};
 if(setrlimit(RLIMIT_CORE,&core)||argc!=2||!valid_home(argv[1])||!confine(argv[1]))goto done;
 const char *library=gpgme_check_version("1.19.0");if(!version(library)||gpgme_new(&ctx))goto done;
 if(gpgme_set_protocol(ctx,GPGME_PROTOCOL_OpenPGP)||gpgme_ctx_set_engine_info(ctx,GPGME_PROTOCOL_OpenPGP,INVENTORY_ENGINE,argv[1]))goto done;
 gpgme_set_offline(ctx,1);gpgme_set_status_cb(ctx,status_error,&status_failed);
 if(gpgme_set_ctx_flag(ctx,"full-status","1"))goto done;
 if(gpgme_set_pinentry_mode(ctx,GPGME_PINENTRY_MODE_ERROR)||gpgme_set_keylist_mode(ctx,GPGME_KEYLIST_MODE_LOCAL)||gpgme_set_ctx_flag(ctx,"auto-key-retrieve","0")||gpgme_set_ctx_flag(ctx,"auto-key-import","0")||gpgme_set_ctx_flag(ctx,"no-auto-check-trustdb","1"))goto done;
 gpgme_engine_info_t engine=gpgme_ctx_get_engine_info(ctx);while(engine&&engine->protocol!=GPGME_PROTOCOL_OpenPGP)engine=engine->next;
 unsigned major=0,minor=0,patch=0;
 if(!engine||!version(engine->version)||strcmp(engine->file_name,INVENTORY_ENGINE)||!engine->home_dir||strcmp(engine->home_dir,argv[1])||sscanf(engine->version,"%u.%u.%u",&major,&minor,&patch)!=3||major<2||(major==2&&(minor<1||(minor==1&&patch<23))))goto done;
 if(!append("{\"version\":1,\"ok\":true,\"protocol\":\"openpgp\",\"gpgme_version\":\"%s\",\"engine_version\":\"%s\",\"keys\":[",library,engine->version)||gpgme_op_keylist_start(ctx,NULL,0))goto done;
 unsigned count=0;
 while(!(err=gpgme_op_keylist_next(ctx,&key))) {
  if(count==32||key->protocol!=GPGME_PROTOCOL_OpenPGP||!key->subkeys)goto done;
  if((count++&&!append(","))||!append("{\"primary\":")||!emit(key->subkeys)||!append(",\"subkeys\":["))goto done;
  unsigned subs=0;for(gpgme_subkey_t sub=key->subkeys->next;sub;sub=sub->next){if(subs==8||(subs++&&!append(","))||!emit(sub))goto done;}
  if(!append("]}"))goto done;gpgme_key_unref(key);key=NULL;
 }
 if(gpg_err_code(err)!=GPG_ERR_EOF||gpgme_op_keylist_end(ctx))goto done;
 gpgme_keylist_result_t result=gpgme_op_keylist_result(ctx);if(status_failed||!result||result->truncated||!append("]}\n"))goto done;
 ok=1;
done:
 if(key)gpgme_key_unref(key);if(ctx)gpgme_release(ctx);
 if(!ok){fputs("{\"version\":1,\"ok\":false,\"error\":\"inventory_unavailable\"}\n",stdout);return 1;}
 return fwrite(output,1,used,stdout)==used?0:1;
}

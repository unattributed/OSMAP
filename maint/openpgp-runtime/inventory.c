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
#include <dirent.h>
#include <errno.h>
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
 if(k->curve){size_t n=strlen(k->curve);if(!n||n>32)return 0;for(size_t i=0;i<n;i++){char c=k->curve[i];if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'))return 0;}}
 return append("{\"fingerprint\":\"%s\",\"algorithm\":%u,\"bits\":%u,\"curve\":%s%s%s,\"created\":%lu,\"expires\":%lu,\"revoked\":%s,\"expired\":%s,\"disabled\":%s,\"invalid\":%s,\"can_sign\":%s,\"can_encrypt\":%s,\"can_certify\":%s,\"can_authenticate\":%s}",k->fpr,(unsigned)k->pubkey_algo,k->length,k->curve?"\"":"",k->curve?k->curve:"null",k->curve?"\"":"",(unsigned long)k->timestamp,(unsigned long)k->expires,k->revoked?"true":"false",k->expired?"true":"false",k->disabled?"true":"false",k->invalid?"true":"false",k->can_sign?"true":"false",k->can_encrypt?"true":"false",k->can_certify?"true":"false",k->can_authenticate?"true":"false");
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
/* Administration is permitted only in a disposable public-only staging home.
 * The authenticated launcher owns actual account locking/CAS and commit. */
static int staging_home(const char *home) {
 DIR *dir=opendir(home);if(!dir)return 0;struct dirent *entry;int ok=1;
 errno=0;
 while((entry=readdir(dir)))if(strcmp(entry->d_name,".")&&strcmp(entry->d_name,"..")&&strcmp(entry->d_name,"pubring.kbx")&&strcmp(entry->d_name,"trustdb.gpg")){ok=0;break;}
 if(errno)ok=0;if(closedir(dir))ok=0;return ok;
}
static int operation_fingerprint(const char *fp) {
 if(!fp||strlen(fp)!=40)return 0;
 for(const char *p=fp;*p;p++)if(!((*p>='0'&&*p<='9')||(*p>='A'&&*p<='F')))return 0;
 return 1;
}
static int trusted_engine(const char *engine) {
 struct stat st;char canonical[4096];
 return engine&&engine[0]=='/'&&realpath(engine,canonical)&&!strcmp(engine,canonical)&&!lstat(engine,&st)&&S_ISREG(st.st_mode)&&(st.st_uid==geteuid()||st.st_uid==0)&&!(st.st_mode&0022)&&(st.st_mode&0111);
}
static gpgme_error_t status_error(void *hook,const char *keyword,const char *args) {
 (void)args;
 /* Record failure while draining the native operation before publication. */
 if(!strcmp(keyword,"ERROR")||!strcmp(keyword,"FAILURE")||!strcmp(keyword,"TRUNCATED"))*(int *)hook=1;
 return 0;
}
static int confine_mode(const char *home,int mutation,const char *engine,int agent_required) {
#ifdef __OpenBSD__
 const char *files[]={INVENTORY_ENGINE,"/usr/local/bin/gpgconf","/usr/libexec/ld.so","/usr/local/lib","/usr/lib","/var/run/ld.so.hints","/etc/localtime","/dev/null","/dev/urandom"};
 const char *perms[]={"rx","rx","rx","r","r","r","r","rw","r"};
 int present[sizeof(files)/sizeof(files[0])];
 for(size_t i=0;i<sizeof(files)/sizeof(files[0]);i++){struct stat st;present[i]=!stat(files[i],&st);}
 /* Public enumeration shares a provisioned agent home, but has no private
  * file or agent socket capability. Unveiling the directory with r would
  * expose private-keys-v1.d to this otherwise public-only process. */
 char path[4096];
 if(agent_required){struct stat st;if(snprintf(path,sizeof(path),"%s/S.gpg-agent",home)>=(int)sizeof(path)||lstat(path,&st)||!S_ISSOCK(st.st_mode)||st.st_uid!=geteuid()||unveil(path,"rw"))return 0;}
 if(unveil(engine,"rx"))return 0;
 if(unveil(home,mutation?"rwc":""))return 0;
 const char *public_files[]={"pubring.kbx","trustdb.gpg"};
 for(size_t i=0;i<2;i++)if(snprintf(path,sizeof(path),"%s/%s",home,public_files[i])>=(int)sizeof(path)||unveil(path,mutation?"rwc":"r"))return 0;
 for(size_t i=0;i<sizeof(files)/sizeof(files[0]);i++)if(present[i]&&unveil(files[i],perms[i]))return 0;
 const char *promises=mutation?"stdio rpath wpath cpath flock unix proc exec error":agent_required?"stdio rpath wpath unix proc exec error":"stdio rpath wpath proc exec error";
 if(unveil(NULL,NULL)||pledge(promises,promises))return 0;
 return 1;
#else
 (void)home;(void)mutation;(void)engine;(void)agent_required;return 0;
#endif
}
static int confine(const char *home) {return confine_mode(home,0,INVENTORY_ENGINE,0);}
static int certificate_envelope(const unsigned char *bytes,size_t size) {
 /* Native GnuPG parses the packets. Bound ASCII armor to exactly one public
  * certificate block so its decoder cannot silently ignore a second payload. */
 const char begin[]="-----BEGIN PGP PUBLIC KEY BLOCK-----",end[]="-----END PGP PUBLIC KEY BLOCK-----";
 if(!size)return 0;if(bytes[0]&0x80)return 1;
 size_t first=sizeof(begin)-1,last=sizeof(end)-1;
 if(size<first+last||memcmp(bytes,begin,first)||(bytes[first]!='\n'&&bytes[first]!='\r'))return 0;
 size_t stop=0;
 for(size_t i=first;i+last<=size;i++) {
  if(i+first<=size&&!memcmp(bytes+i,begin,first))return 0;
  if(!memcmp(bytes+i,end,last)){if(stop)return 0;stop=i+last;}
 }
 if(!stop)return 0;
 for(size_t i=stop;i<size;i++)if(bytes[i]!='\r'&&bytes[i]!='\n'&&bytes[i]!=' '&&bytes[i]!='\t')return 0;
 return 1;
}
static int public_import(gpgme_ctx_t ctx,const char *expected,int *status_failed) {
 unsigned char input[LIMIT+1];size_t size=fread(input,1,sizeof(input),stdin);
 if(ferror(stdin)||!size||size>LIMIT||!certificate_envelope(input,size))return 0;
 gpgme_data_t data=NULL;gpgme_key_t key=NULL;gpgme_error_t err;int ok=0;
 if(gpgme_data_new_from_mem(&data,(const char *)input,size,0)||gpgme_set_keylist_mode(ctx,GPGME_KEYLIST_MODE_LOCAL|GPGME_KEYLIST_MODE_WITH_SECRET)||gpgme_op_keylist_from_data_start(ctx,data,0))goto done;
 unsigned count=0;int valid=1;
 while(!(err=gpgme_op_keylist_next(ctx,&key))) {
  if(count++||key->protocol!=GPGME_PROTOCOL_OpenPGP||!key->subkeys||!key->subkeys->fpr||strcmp(key->subkeys->fpr,expected)||key->secret)valid=0;
  unsigned subkeys=0;
  for(gpgme_subkey_t sub=key->subkeys;sub;sub=sub->next)if(subkeys++>=9||sub->secret||!operation_fingerprint(sub->fpr))valid=0;
  gpgme_key_unref(key);key=NULL;
 }
 gpgme_error_t ended=gpgme_op_keylist_end(ctx);
 if(gpg_err_code(err)!=GPG_ERR_EOF||ended||count!=1||!valid||*status_failed)goto done;
 gpgme_keylist_result_t preview=gpgme_op_keylist_result(ctx);
 if(!preview||preview->truncated||gpgme_set_keylist_mode(ctx,GPGME_KEYLIST_MODE_LOCAL)||gpgme_data_seek(data,0,SEEK_SET)!=0||gpgme_op_import(ctx,data)||*status_failed)goto done;
 gpgme_import_result_t imported=gpgme_op_import_result(ctx);
 if(!imported||imported->considered!=1||imported->secret_read||imported->secret_imported||imported->secret_unchanged||imported->not_imported||!imported->imports||imported->imports->next||imported->imports->result||!imported->imports->fpr||strcmp(imported->imports->fpr,expected)||(imported->imports->status&GPGME_IMPORT_SECRET))goto done;
 ok=1;
done:
 if(key)gpgme_key_unref(key);if(data)gpgme_data_release(data);return ok;
}
static int public_remove(gpgme_ctx_t ctx,const char *expected,int *status_failed) {
 if(fgetc(stdin)!=EOF||ferror(stdin))return 0;
 gpgme_key_t key=NULL;int ok=0;
 if(gpgme_get_key(ctx,expected,&key,0)||!key||key->protocol!=GPGME_PROTOCOL_OpenPGP||!key->subkeys||!key->subkeys->fpr||strcmp(key->subkeys->fpr,expected))goto done;
 /* Never ALLOW_SECRET. The launcher must independently refuse actual account
  * secret-key capabilities before staging because staging is public-only. */
 if(gpgme_op_delete_ext(ctx,key,GPGME_DELETE_FORCE)||*status_failed)goto done;
 ok=1;
done:
 if(key)gpgme_key_unref(key);return ok;
}
static int guard_removal(gpgme_ctx_t ctx,const char *expected,int *status_failed) {
 if(fgetc(stdin)!=EOF||ferror(stdin))return 0;
 gpgme_key_t key=NULL;int ok=0;
 if(gpgme_set_keylist_mode(ctx,GPGME_KEYLIST_MODE_LOCAL|GPGME_KEYLIST_MODE_WITH_SECRET)||gpgme_get_key(ctx,expected,&key,0)||!key||key->protocol!=GPGME_PROTOCOL_OpenPGP||!key->subkeys||!key->subkeys->fpr||strcmp(key->subkeys->fpr,expected)||key->secret||*status_failed)goto done;
 for(gpgme_subkey_t sub=key->subkeys;sub;sub=sub->next)if(sub->secret)goto done;
 if(gpgme_set_keylist_mode(ctx,GPGME_KEYLIST_MODE_LOCAL))goto done;
 ok=1;
done:
 if(key)gpgme_key_unref(key);return ok;
}
int main(int argc,char **argv) {
#ifdef __OpenBSD__
 closefrom(3);
#endif
 gpgme_ctx_t ctx=NULL;gpgme_key_t key=NULL;gpgme_error_t err;int ok=0,status_failed=0;struct rlimit core={0,0};
 int selected=argc==5,guard=selected&&!strcmp(argv[2],"guard-removal"),mutation=selected&&!guard;const char *engine_path=selected?argv[4]:INVENTORY_ENGINE;
 if(setrlimit(RLIMIT_CORE,&core)||(argc!=2&&!selected)||!valid_home(argv[1]))goto done;
 if(selected&&(!operation_fingerprint(argv[3])||!trusted_engine(engine_path)||!strcmp(engine_path,INVENTORY_ENGINE)))goto done;
 if(mutation) {
  struct rlimit cpu={10,10},data={128*1024*1024,128*1024*1024},files={4*1024*1024,4*1024*1024};
  if((strcmp(argv[2],"import-public")&&strcmp(argv[2],"remove-public"))||!staging_home(argv[1])||setrlimit(RLIMIT_CPU,&cpu)||setrlimit(RLIMIT_DATA,&data)||setrlimit(RLIMIT_FSIZE,&files)||!confine_mode(argv[1],1,engine_path,0))goto done;
 } else if(guard?!confine_mode(argv[1],0,engine_path,1):!confine(argv[1]))goto done;
 const char *library=gpgme_check_version("1.19.0");if(!version(library)||gpgme_new(&ctx))goto done;
 if(gpgme_set_protocol(ctx,GPGME_PROTOCOL_OpenPGP)||gpgme_ctx_set_engine_info(ctx,GPGME_PROTOCOL_OpenPGP,engine_path,argv[1]))goto done;
 gpgme_set_offline(ctx,1);gpgme_set_status_cb(ctx,status_error,&status_failed);
 if(gpgme_set_ctx_flag(ctx,"full-status","1"))goto done;
 if(gpgme_set_pinentry_mode(ctx,GPGME_PINENTRY_MODE_ERROR)||gpgme_set_keylist_mode(ctx,GPGME_KEYLIST_MODE_LOCAL)||gpgme_set_ctx_flag(ctx,"auto-key-retrieve","0")||gpgme_set_ctx_flag(ctx,"auto-key-import","0")||gpgme_set_ctx_flag(ctx,"no-auto-check-trustdb","1"))goto done;
 gpgme_engine_info_t engine=gpgme_ctx_get_engine_info(ctx);while(engine&&engine->protocol!=GPGME_PROTOCOL_OpenPGP)engine=engine->next;
 unsigned major=0,minor=0,patch=0;
 if(!engine||!version(engine->version)||strcmp(engine->file_name,engine_path)||!engine->home_dir||strcmp(engine->home_dir,argv[1])||sscanf(engine->version,"%u.%u.%u",&major,&minor,&patch)!=3||major<2||(major==2&&(minor<1||(minor==1&&patch<23))))goto done;
 if(mutation&&!(strcmp(argv[2],"import-public")?public_remove(ctx,argv[3],&status_failed):public_import(ctx,argv[3],&status_failed)))goto done;
 if(guard&&!guard_removal(ctx,argv[3],&status_failed))goto done;
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

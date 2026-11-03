/* Per-account GPGME worker. Trusted launcher supplies home/engine paths, never
 * the wire caller. Binary stdin: OSMC, op, key count, reserved 0, content/signature
 * lengths, 64-byte NUL-padded full fingerprints, content, detached signature.
 * Stdout: metadata length/body length (BE32), strict v1 JSON, body. Failed
 * operations emit metadata only and never any partial plaintext. */
#include <gpgme.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <time.h>
#ifdef __OpenBSD__
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#endif
#define CONTENT_LIMIT (16U * 1024U * 1024U)
#define KEY_LIMIT 50
#ifndef CRYPTO_GPG
#define CRYPTO_GPG "/usr/local/bin/gpg"
#endif
static char fingerprints[KEY_LIMIT][65], decrypt_primary[65];
static unsigned key_count, status_failed, cipher_ok, cipher_seen, decrypt_key_ok, valid_signature_seen;
struct buffer { unsigned char *bytes; size_t size, position; int overflow; };
static int fp_valid(const char *s) {
 size_t n = s ? strlen(s) : 0;
 if (n != 40 && n != 64) return 0;
 for (size_t i = 0; i < n; i++)
  if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'A' && s[i] <= 'F'))) return 0;
 return 1;
}
static ssize_t bounded_write(void *handle, const void *bytes, size_t size) {
 struct buffer *b = handle;
 if (size > CONTENT_LIMIT - b->position) { b->overflow = 1; errno = EFBIG; return -1; }
 memcpy(b->bytes + b->position, bytes, size); b->position += size;
 if (b->position > b->size) b->size = b->position;
 return (ssize_t)size;
}
static off_t bounded_seek(void *handle, off_t offset, int whence) {
 struct buffer *b = handle;
 off_t base = whence == SEEK_SET ? 0 : whence == SEEK_CUR ? (off_t)b->position : whence == SEEK_END ? (off_t)b->size : -1;
 if (base < 0 || offset < -base || offset > (off_t)CONTENT_LIMIT - base) { errno = EINVAL; return -1; }
 b->position = (size_t)(base + offset); return (off_t)b->position;
}
static uint32_t number(const unsigned char *p) { return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static int read_exact(void *p, size_t n) { return !n || fread(p, 1, n, stdin) == n; }
static int write_number(uint32_t n) {
 unsigned char b[] = {(unsigned char)(n>>24),(unsigned char)(n>>16),(unsigned char)(n>>8),(unsigned char)n};
 return fwrite(b, 1, sizeof(b), stdout) == sizeof(b);
}
/* unveil does not revoke capabilities carried by already-open descriptors.
 * Retain only the three reviewed worker transport descriptors before loading
 * account state. GPGME subsequently creates its own engine transport pipes. */
static void close_inherited_descriptors(void) {
#ifdef __OpenBSD__
 closefrom(3);
#endif
}
static int private_file(const char *home, const char *name) {
 char path[4096]; struct stat st;
 int n = snprintf(path, sizeof(path), "%s/%s", home, name);
 return n > 0 && (size_t)n < sizeof(path) && !lstat(path, &st) && S_ISREG(st.st_mode) && st.st_uid == geteuid() && !(st.st_mode & 0077);
}
static int trusted_paths(const char *home, const char *engine) {
 struct stat st; char actual[4096], path[4096];
 if (!home || home[0] != '/' || !realpath(home, actual) || strcmp(home, actual) || lstat(home, &st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0777) != 0700 || !private_file(home,"pubring.kbx") || !private_file(home,"trustdb.gpg")) return 0;
 if (!engine || engine[0] != '/' || !realpath(engine,actual) || strcmp(engine,actual) || lstat(engine,&st) || !S_ISREG(st.st_mode) || (st.st_uid != 0 && st.st_uid != geteuid()) || (st.st_mode & 0022) || !(st.st_mode & 0111)) return 0;
 const char *configs[] = {"gpg.conf", "common.conf", "gpg-agent.conf"};
 for (size_t i=0;i<3;i++) { if (snprintf(path,sizeof(path),"%s/%s",home,configs[i]) >= (int)sizeof(path) || !lstat(path,&st)) return 0; }
 return 1;
}
#ifdef __OpenBSD__
/* A pathname alone does not establish a running agent. Exchange no protocol or
 * secret; refuse a dead/foreign/replaced endpoint before GPG can misreport it
 * as absent private material. Public operations never call this preflight. */
static int live_private_agent(const char *path, const struct stat *before) {
 struct sockaddr_un address; memset(&address,0,sizeof(address));
 if(strlen(path)>=sizeof(address.sun_path))return 0;
 address.sun_family=AF_UNIX;address.sun_len=sizeof(address);
 strlcpy(address.sun_path,path,sizeof(address.sun_path));
 int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
 if(fd<0)return 0;
 int ok=connect(fd,(struct sockaddr *)&address,sizeof(address))==0;
 if(!ok && (errno==EINPROGRESS || errno==EAGAIN)) {
  struct pollfd ready={fd,POLLOUT,0};int error=0;socklen_t size=sizeof(error);
  ok=poll(&ready,1,250)>0 && (ready.revents&POLLOUT) &&
   getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)==0 && error==0;
 }
 uid_t uid;gid_t gid;struct stat after;
 ok=ok && getpeereid(fd,&uid,&gid)==0 && uid==geteuid() && !lstat(path,&after) &&
  after.st_dev==before->st_dev && after.st_ino==before->st_ino &&
  after.st_uid==before->st_uid && after.st_gid==before->st_gid &&
  after.st_mode==before->st_mode && after.st_nlink==before->st_nlink &&
  after.st_ctim.tv_sec==before->st_ctim.tv_sec && after.st_ctim.tv_nsec==before->st_ctim.tv_nsec;
 close(fd);return ok;
}
#endif
static int confine_mode(const char *home, const char *engine, int agent_required, int personal_import) {
#ifdef __OpenBSD__
 char path[4096]; struct stat st;
 const char *files[] = {CRYPTO_GPG, "/usr/local/bin/gpgconf", "/usr/libexec/ld.so", "/usr/local/lib", "/usr/lib", "/var/run/ld.so.hints", "/etc/localtime", "/dev/null", "/dev/urandom"};
 const char *perms[] = {"rx", "rx", "rx", "r", "r", "r", "r", "rw", "r"};
 int present[sizeof(files)/sizeof(files[0])];
 for(size_t i=0;i<sizeof(files)/sizeof(files[0]);i++)present[i]=!stat(files[i],&st);
 char agent[4096];
 if(agent_required && (snprintf(agent,sizeof(agent),"%s/S.gpg-agent",home)>=(int)sizeof(agent) || lstat(agent,&st) || !S_ISSOCK(st.st_mode) || st.st_uid!=geteuid() || st.st_nlink!=1 || !live_private_agent(agent,&st)))return 0;
 if (unveil(home, personal_import?"rwc":"") || unveil(engine,"rx")) return 0;
 const char *public_files[] = {"pubring.kbx", "trustdb.gpg"};
 for (size_t i=0;i<2;i++) { if (snprintf(path,sizeof(path),"%s/%s",home,public_files[i]) >= (int)sizeof(path) || unveil(path,personal_import?"rwc":"r")) return 0; }
 if (agent_required && unveil(agent,"rw"))return 0;
 for (size_t i=0;i<sizeof(files)/sizeof(files[0]);i++) if (present[i] && unveil(files[i],perms[i])) return 0;
 const char *promises=personal_import?"stdio rpath wpath cpath flock unix proc exec error":"stdio rpath wpath unix proc exec error";
 if (unveil(NULL,NULL) || pledge(promises,promises)) return 0;
 return 1;
#else
 (void)home; (void)engine; (void)agent_required; (void)personal_import; return 0;
#endif
}
static int confine(const char *home,const char *engine,int agent_required) {return confine_mode(home,engine,agent_required,0);}
static gpgme_error_t status_callback(void *unused,const char *keyword,const char *args) {
 (void)unused;
 if (!strcmp(keyword,"TRUNCATED") || !strcmp(keyword,"FAILURE") || !strcmp(keyword,"ERROR")) status_failed = 1;
 if (!strcmp(keyword,"VALIDSIG")) {
  unsigned version=0,hash=0;
  if(valid_signature_seen++ || sscanf(args,"%*s %*s %*s %*s %u %*s %*s %u",&version,&hash)!=2 || version!=4 || (hash!=8 && hash!=10))status_failed=1;
 }
 if (!strcmp(keyword,"DECRYPTION_INFO") || !strcmp(keyword,"BEGIN_ENCRYPTION")) {
  unsigned mdc=0,cipher=0,aead=0,compliance_error=0;char extra;
  int n=sscanf(args,"%u %u %u %u %c",&mdc,&cipher,&aead,&compliance_error,&extra);
  if(cipher_seen++)status_failed=1;
  cipher_ok = n >= 2 && n <= 4 && !compliance_error && cipher == 9 && ((mdc == 2 && aead == 0) || (mdc == 0 && aead == 2));
 }
 if (!strcmp(keyword,"DECRYPTION_KEY")) {
  char sub[65],primary[65];
  if (sscanf(args,"%64s %64s",sub,primary)==2 && fp_valid(sub) && fp_valid(primary)) {
   for (unsigned i=0;i<key_count;i++) if (!strcmp(primary,fingerprints[i])) { strcpy(decrypt_primary,primary); decrypt_key_ok=1; }
  }
 }
 return 0;
}
static int qualified_material(gpgme_subkey_t s) {
 if ((s->pubkey_algo == GPGME_PK_RSA || s->pubkey_algo == GPGME_PK_RSA_S || s->pubkey_algo == GPGME_PK_RSA_E) && s->length >= 3072) return 1;
 if (s->pubkey_algo == GPGME_PK_EDDSA && s->curve && !strcmp(s->curve,"ed25519")) return 1;
 return s->pubkey_algo == GPGME_PK_ECDH && s->curve && !strcmp(s->curve,"cv25519");
}
static int allowed_algorithm(gpgme_subkey_t s,int purpose) {
 if ((s->pubkey_algo == GPGME_PK_RSA || (purpose==1 && s->pubkey_algo == GPGME_PK_RSA_S) || (purpose==2 && s->pubkey_algo == GPGME_PK_RSA_E)) && s->length >= 3072) return 1;
 if (purpose==1 && s->pubkey_algo == GPGME_PK_EDDSA && s->curve && !strcmp(s->curve,"ed25519")) return 1;
 return purpose==2 && s->pubkey_algo == GPGME_PK_ECDH && s->curve && !strcmp(s->curve,"cv25519");
}
static int usable(gpgme_key_t key, const char *fingerprint, int purpose, int exact_primary) {
 if (!key || key->protocol != GPGME_PROTOCOL_OpenPGP || !key->subkeys || !fp_valid(key->subkeys->fpr) || strlen(key->subkeys->fpr)!=40 || key->revoked || key->expired || key->disabled || key->invalid || !qualified_material(key->subkeys)) return 0;
 if (exact_primary && strcmp(key->subkeys->fpr,fingerprint)) return 0;
 unsigned candidates=0,capable=0;
 for (gpgme_subkey_t s=key->subkeys;s;s=s->next) {
  if (!fp_valid(s->fpr) || strlen(s->fpr)!=40 || (int64_t)s->expires < 0 || (int64_t)s->timestamp < 0 || (uint64_t)s->timestamp > (uint64_t)time(NULL)) return 0;
  if (s->revoked || s->expired || s->disabled || s->invalid || (s->expires && (uint64_t)s->expires <= (uint64_t)time(NULL))) continue;
  if (!(purpose==1 ? s->can_sign : s->can_encrypt)) continue;
  if (purpose==1 && fingerprint && strcmp(s->fpr,fingerprint)) continue;
  if (!allowed_algorithm(s,purpose) || ++capable > 1) return 0;
  candidates++;
 }
 return candidates == 1; /* Never silently choose among capable subkeys. */
}
static const char *failure(gpgme_error_t err) {
 switch (gpg_err_code(err)) {
 case GPG_ERR_NO_PIN_ENTRY: case GPG_ERR_BAD_PASSPHRASE: case GPG_ERR_CANCELED: return "locked";
 case GPG_ERR_NO_SECKEY: case GPG_ERR_NO_PUBKEY: return "missing_key";
 default: return "unavailable";
 }
}
static const char *decrypt_failure(gpgme_error_t err, gpgme_decrypt_result_t r, int output_failed) {
 if(output_failed)return "unavailable";
 if(gpg_err_code(err)==GPG_ERR_NO_DATA || gpg_err_code(err)==GPG_ERR_BAD_DATA)return "unsupported";
 if(gpg_err_code(err)==GPG_ERR_DECRYPT_FAILED && r) {
  /* The aggregate error can hide missing recipient keys. Do not mistake an
   * invalid/non-public-key packet for missing private material, or an output
   * bound failure for a cryptographic verdict. No content is released here. */
  if(!r->recipients)return "unsupported";
  unsigned count=0;int all_missing=1;
  for(gpgme_recipient_t recipient=r->recipients;recipient;recipient=recipient->next) {
   if(++count>KEY_LIMIT || gpg_err_code(recipient->status)!=GPG_ERR_NO_SECKEY) {all_missing=0;break;}
  }
  if(count && all_missing)return "missing_key";
 }
 return failure(err);
}
struct personal_secret { unsigned char *bytes; size_t size; unsigned calls; };
static gpgme_error_t personal_passphrase(void *opaque,const char *uid,const char *info,int bad,int fd) {
 (void)uid;(void)info;struct personal_secret *secret=opaque;
 if(bad||secret->calls++>=16)return gpg_error(GPG_ERR_BAD_PASSPHRASE);
 size_t offset=0;while(offset<secret->size){ssize_t n=write(fd,secret->bytes+offset,secret->size-offset);if(n<0&&errno==EINTR)continue;if(n<=0)return gpg_error(GPG_ERR_EIO);offset+=(size_t)n;}
 return write(fd,"\n",1)==1?0:gpg_error(GPG_ERR_EIO);
}
static int personal_identity(gpgme_key_t key,const char *account) {
 const char *at=strrchr(account,'@');if(!at)return 0;
 unsigned count=0;for(gpgme_user_id_t uid=key->uids;uid;uid=uid->next){
  if(++count>32)return 0;if(uid->revoked||uid->invalid)continue;
  const char *email=uid->email&&*uid->email?uid->email:uid->address;if(!email)continue;
  const char *other=strrchr(email,'@');if(!other)continue;
  if((size_t)(at-account)==(size_t)(other-email)&&!memcmp(account,email,(size_t)(at-account))&&!strcasecmp(at+1,other+1))return 1;
 }return 0;
}
static int personal_main(const char *home,const char *engine) {
 unsigned char header[143],*certificate=NULL,*passphrase=NULL;char primary[65],signer[65],account[255];
 uint32_t certificate_size=0,passphrase_size=0;
 gpgme_ctx_t ctx=NULL;gpgme_key_t key=NULL,signing=NULL;gpgme_data_t imported=NULL,input=NULL,signature=NULL,cipher=NULL,plain=NULL;
 const char *error="invalid";int ok=0;gpgme_error_t err=0;struct personal_secret secret={0};
 struct rlimit core={0,0},cpu={10,10},files={4U*1024U*1024U,4U*1024U*1024U},memory={256U*1024U*1024U,256U*1024U*1024U};
 if(setrlimit(RLIMIT_CORE,&core)||setrlimit(RLIMIT_CPU,&cpu)||setrlimit(RLIMIT_FSIZE,&files)||setrlimit(RLIMIT_DATA,&memory)||!trusted_paths(home,engine)||!read_exact(header,sizeof(header))||memcmp(header,"OSMP",4)||(header[4]!=1&&header[4]!=2))goto done;
 memcpy(primary,header+5,64);primary[64]=0;memcpy(signer,header+69,64);signer[64]=0;
 unsigned account_size=((unsigned)header[133]<<8)|header[134];certificate_size=number(header+135);passphrase_size=number(header+139);
 if(!fp_valid(primary)||strlen(primary)!=40||!fp_valid(signer)||strlen(signer)!=40||!account_size||account_size>=sizeof(account)||certificate_size>65536||passphrase_size>1024||(header[4]==1?!certificate_size:certificate_size))goto done;
 for(size_t i=40;i<64;i++)if(header[5+i]||header[69+i])goto done;
 if(!read_exact(account,account_size))goto done;account[account_size]=0;
 for(unsigned i=0;i<account_size;i++)if((unsigned char)account[i]<33||account[i]==127)goto done;
 certificate=malloc(certificate_size?certificate_size:1);passphrase=malloc(passphrase_size?passphrase_size:1);
 if(!certificate||!passphrase||!read_exact(certificate,certificate_size)||!read_exact(passphrase,passphrase_size)||fgetc(stdin)!=EOF)goto done;
 for(uint32_t i=0;i<passphrase_size;i++)if(!passphrase[i]||passphrase[i]=='\n'||passphrase[i]=='\r')goto done;
 if(!confine_mode(home,engine,1,header[4]==1))goto done;
 error="unavailable";
 if(!gpgme_check_version("2.0.1")||gpgme_new(&ctx)||gpgme_set_protocol(ctx,GPGME_PROTOCOL_OpenPGP)||gpgme_ctx_set_engine_info(ctx,GPGME_PROTOCOL_OpenPGP,engine,home))goto done;
 secret.bytes=passphrase;secret.size=passphrase_size;
 gpgme_set_offline(ctx,1);gpgme_set_passphrase_cb(ctx,personal_passphrase,&secret);gpgme_set_status_cb(ctx,status_callback,NULL);
 if(gpgme_set_pinentry_mode(ctx,GPGME_PINENTRY_MODE_LOOPBACK)||gpgme_set_keylist_mode(ctx,GPGME_KEYLIST_MODE_LOCAL)||gpgme_set_ctx_flag(ctx,"full-status","1")||gpgme_set_ctx_flag(ctx,"auto-key-retrieve","0")||gpgme_set_ctx_flag(ctx,"auto-key-import","0")||gpgme_set_ctx_flag(ctx,"no-auto-check-trustdb","1"))goto done;
 if(header[4]==1){
  error="invalid";
  if(gpgme_data_new_from_mem(&imported,(char *)certificate,certificate_size,0)||gpgme_set_keylist_mode(ctx,GPGME_KEYLIST_MODE_LOCAL|GPGME_KEYLIST_MODE_WITH_SECRET)||gpgme_op_keylist_from_data_start(ctx,imported,0))goto done;
  unsigned count=0;int valid=1;while(!(err=gpgme_op_keylist_next(ctx,&key))){if(++count!=1||!key->secret||!key->subkeys||!key->subkeys->fpr||strcmp(key->subkeys->fpr,primary)||!personal_identity(key,account))valid=0;gpgme_key_unref(key);key=NULL;}
  if(gpgme_op_keylist_end(ctx)||gpg_err_code(err)!=GPG_ERR_EOF||!valid||count!=1||gpgme_set_keylist_mode(ctx,GPGME_KEYLIST_MODE_LOCAL)||gpgme_data_seek(imported,0,SEEK_SET)!=0)goto done;
  err=gpgme_op_import(ctx,imported);if(err){error=failure(err);goto done;}
  gpgme_import_result_t result=gpgme_op_import_result(ctx);
  if(!result||result->considered!=1||result->secret_read!=1||result->secret_imported!=1||result->not_imported||!result->imports)goto done;
  unsigned reports=0,secret_report=0;
  for(gpgme_import_status_t record=result->imports;record;record=record->next){
   if(++reports>2||record->result||!record->fpr||strcmp(record->fpr,primary))goto done;
   if(record->status&GPGME_IMPORT_SECRET)secret_report=1;
  }
  if(!secret_report)goto done;
 }
 error="unsupported";
 if(gpgme_get_key(ctx,primary,&key,0)||!key||!key->subkeys||strcmp(key->subkeys->fpr,primary)||!personal_identity(key,account)||!usable(key,primary,2,1)||gpgme_get_key(ctx,signer,&signing,0)||!signing||!signing->subkeys||strcmp(signing->subkeys->fpr,primary)||!usable(signing,signer,1,0))goto done;
 const char challenge[]="OSMAP personal private-key proof\r\n";
 if(gpgme_data_new_from_mem(&input,challenge,sizeof(challenge)-1,0)||gpgme_data_new(&signature)||gpgme_data_new(&cipher)||gpgme_data_new(&plain)||gpgme_signers_add(ctx,signing))goto done;
 status_failed=0;valid_signature_seen=0;err=gpgme_op_sign(ctx,input,signature,GPGME_SIG_MODE_DETACH);if(err){error=failure(err);goto done;}
 gpgme_sign_result_t signed_result=gpgme_op_sign_result(ctx);
 if(!signed_result||signed_result->invalid_signers||!signed_result->signatures||signed_result->signatures->next||!signed_result->signatures->fpr||strcmp(signed_result->signatures->fpr,signer))goto done;
 if(gpgme_data_seek(signature,0,SEEK_SET)!=0||gpgme_data_seek(input,0,SEEK_SET)!=0)goto done;
 err=gpgme_op_verify(ctx,signature,input,NULL);gpgme_verify_result_t verified=gpgme_op_verify_result(ctx);gpgme_signature_t checked=verified?verified->signatures:NULL;
 if(err||!checked||checked->next||checked->status||!checked->fpr||strcmp(checked->fpr,signer)||valid_signature_seen!=1||status_failed)goto done;
 if(gpgme_data_seek(input,0,SEEK_SET)!=0)goto done;
 status_failed=0;cipher_seen=0;cipher_ok=0;gpgme_key_t recipients[]={key,NULL};
 err=gpgme_op_encrypt(ctx,recipients,GPGME_ENCRYPT_ALWAYS_TRUST,input,cipher);if(err||!cipher_ok||status_failed)goto done;
 if(gpgme_data_seek(cipher,0,SEEK_SET)!=0)goto done;
 strcpy(fingerprints[0],primary);key_count=1;status_failed=0;cipher_seen=0;cipher_ok=0;decrypt_key_ok=0;
 err=gpgme_op_decrypt(ctx,cipher,plain);if(err){error=failure(err);goto done;}
 if(!cipher_ok||!decrypt_key_ok||status_failed||gpgme_data_seek(plain,0,SEEK_SET)!=0)goto done;
 char recovered[sizeof(challenge)];ssize_t size=gpgme_data_read(plain,recovered,sizeof(recovered));
 if(size!=(ssize_t)(sizeof(challenge)-1)||memcmp(recovered,challenge,sizeof(challenge)-1))goto done;
 memset(recovered,0,sizeof(recovered));ok=1;
done:
 if(imported)gpgme_data_release(imported);if(input)gpgme_data_release(input);if(signature)gpgme_data_release(signature);if(cipher)gpgme_data_release(cipher);if(plain)gpgme_data_release(plain);
 if(key)gpgme_key_unref(key);if(signing)gpgme_key_unref(signing);if(ctx)gpgme_release(ctx);
 if(certificate){memset(certificate,0,certificate_size);free(certificate);}if(passphrase){memset(passphrase,0,passphrase_size);free(passphrase);}
 if(ok)fputs("{\"ok\":true}\n",stdout);else fprintf(stdout,"{\"ok\":false,\"error\":\"%s\"}\n",error);
 return ok?0:1;
}
int main(int argc,char **argv) {
 close_inherited_descriptors();
 if(argc==4&&!strcmp(argv[3],"--personal"))return personal_main(argv[1],argv[2]);
 gpgme_ctx_t ctx=NULL; gpgme_data_t input=NULL,detached=NULL,output=NULL;
 gpgme_key_t selected[KEY_LIMIT+1]={0}; gpgme_error_t err=0;
 struct rlimit core={0,0},cpu={10,10},filesize={0,0},memory={256U*1024U*1024U,256U*1024U*1024U};
 unsigned char header[16],*content=NULL,*signature=NULL;
 unsigned op=0; uint32_t content_size=0,signature_size=0;
 struct buffer result={0}; char metadata[1024],signer[65]="",primary[65]="";
 const char *error="invalid",*operation="invalid"; unsigned hash=0; int success=0;
 if (setrlimit(RLIMIT_CORE,&core) || setrlimit(RLIMIT_CPU,&cpu) || setrlimit(RLIMIT_FSIZE,&filesize) || setrlimit(RLIMIT_DATA,&memory) || argc!=3 || !trusted_paths(argv[1],argv[2])) goto done;
 if (!read_exact(header,sizeof(header)) || memcmp(header,"OSMC",4) || header[6] || header[7]) goto done;
 op=header[4]; key_count=header[5]; content_size=number(header+8); signature_size=number(header+12);
 if (op<1 || op>4 || key_count>KEY_LIMIT || !content_size || content_size>CONTENT_LIMIT || signature_size>CONTENT_LIMIT-content_size || (op==2 ? (!signature_size || key_count) : signature_size!=0) || (op==3 && key_count!=1) || ((op==1 || op==4) && !key_count)) goto done;
 operation = op==1?"decrypt":op==2?"verify":op==3?"sign":"encrypt";
 for (unsigned i=0;i<key_count;i++) {
  if (!read_exact(fingerprints[i],64)) goto done;
  fingerprints[i][64]=0;
  if (!fp_valid(fingerprints[i])) goto done;
  for (size_t j=strlen(fingerprints[i]);j<64;j++) if (fingerprints[i][j]) goto done;
  for (unsigned j=0;j<i;j++) if (!strcmp(fingerprints[i],fingerprints[j])) goto done;
 }
 content=malloc(content_size); if(signature_size)signature=malloc(signature_size); result.bytes=malloc(CONTENT_LIMIT);
 if (!content || (signature_size&&!signature) || !result.bytes || !read_exact(content,content_size) || !read_exact(signature,signature_size) || fgetc(stdin)!=EOF) goto done;
 error="unavailable";
 if (!confine(argv[1],argv[2],op==1 || op==3)) { error=(op==1 || op==3)?"locked":"unavailable"; goto done; }
 if (!gpgme_check_version("2.0.1") || gpgme_new(&ctx) || gpgme_set_protocol(ctx,GPGME_PROTOCOL_OpenPGP) || gpgme_ctx_set_engine_info(ctx,GPGME_PROTOCOL_OpenPGP,argv[2],argv[1])) goto done;
 gpgme_set_offline(ctx,1); gpgme_set_armor(ctx,1); gpgme_set_textmode(ctx,0); gpgme_set_status_cb(ctx,status_callback,NULL);
 if (gpgme_set_pinentry_mode(ctx,GPGME_PINENTRY_MODE_ERROR) || gpgme_set_keylist_mode(ctx,GPGME_KEYLIST_MODE_LOCAL) || gpgme_set_ctx_flag(ctx,"full-status","1") || gpgme_set_ctx_flag(ctx,"auto-key-retrieve","0") || gpgme_set_ctx_flag(ctx,"auto-key-import","0") || gpgme_set_ctx_flag(ctx,"no-auto-check-trustdb","1")) goto done;
 if (gpgme_data_new_from_mem(&input,(char *)content,content_size,0)) goto done;
 struct gpgme_data_cbs callbacks={NULL,bounded_write,bounded_seek,NULL};
 if (gpgme_data_new_from_cbs(&output,&callbacks,&result)) goto done;
 if (op==3 || op==4) {
  for (unsigned i=0;i<key_count;i++) {
   char selector[66];const char *pattern=fingerprints[i];
   if(op==3){snprintf(selector,sizeof(selector),"%s!",fingerprints[i]);pattern=selector;}
   err=gpgme_get_key(ctx,pattern,&selected[i],0);
   if(err) {error=failure(err);goto done;}
   if(!usable(selected[i],fingerprints[i],op==3?1:2,op==4)) {error="unsupported";goto done;}
  }
 }
 if (op==1) {
  err=gpgme_op_decrypt(ctx,input,output);
  gpgme_decrypt_result_t r=gpgme_op_decrypt_result(ctx);
  if(err) {error=decrypt_failure(err,r,result.overflow);goto done;}
  if(!r || r->unsupported_algorithm || r->wrong_key_usage || r->legacy_cipher_nomdc || !cipher_ok || !decrypt_key_ok) {error="integrity";goto done;}
  strcpy(primary,decrypt_primary);
  err=gpgme_get_key(ctx,primary,&selected[0],0);
  if(err || !usable(selected[0],primary,2,1)) {error="unsupported";goto done;}
 } else if (op==2) {
  if(gpgme_data_new_from_mem(&detached,(char *)signature,signature_size,0))goto done;
  err=gpgme_op_verify(ctx,detached,input,NULL);
  gpgme_verify_result_t r=gpgme_op_verify_result(ctx); gpgme_signature_t s=r?r->signatures:NULL;
  /* Missing public material is distinct from a bad signature. Only a single
   * explicitly missing-key result qualifies; multiple/ambiguous signatures
   * still take the signature-failure path and never release content. */
  if(!err && s && !s->next && gpg_err_code(s->status)==GPG_ERR_NO_PUBKEY && (s->summary&GPGME_SIGSUM_KEY_MISSING)) {error="missing_key";goto done;}
  if(err || !s || s->next || s->status || !fp_valid(s->fpr) || valid_signature_seen!=1 || s->wrong_key_usage || (s->summary & ~(GPGME_SIGSUM_VALID|GPGME_SIGSUM_GREEN)) || (s->hash_algo!=GPGME_MD_SHA256 && s->hash_algo!=GPGME_MD_SHA512)) {error="signature";goto done;}
  strcpy(signer,s->fpr);hash=(unsigned)s->hash_algo;
  err=gpgme_get_key(ctx,signer,&selected[0],0);
  if(err || !usable(selected[0],signer,1,0)) {error="unsupported";goto done;}
  strcpy(primary,selected[0]->subkeys->fpr);
 } else if (op==3) {
  if(gpgme_signers_add(ctx,selected[0]))goto done;
  err=gpgme_op_sign(ctx,input,output,GPGME_SIG_MODE_DETACH);
  if(err) {error=failure(err);goto done;}
  gpgme_sign_result_t r=gpgme_op_sign_result(ctx);gpgme_new_signature_t s=r?r->signatures:NULL;
  if(!r || r->invalid_signers || !s || s->next || !fp_valid(s->fpr) || (s->hash_algo!=GPGME_MD_SHA256 && s->hash_algo!=GPGME_MD_SHA512) || !usable(selected[0],s->fpr,1,0) || strcmp(fingerprints[0],s->fpr)) {error="signature";goto done;}
  strcpy(signer,s->fpr);strcpy(primary,selected[0]->subkeys->fpr);hash=(unsigned)s->hash_algo;
 } else {
  err=gpgme_op_encrypt(ctx,selected,GPGME_ENCRYPT_ALWAYS_TRUST|GPGME_ENCRYPT_THROW_KEYIDS,input,output);
  if(err) {error=failure(err);goto done;}
  gpgme_encrypt_result_t r=gpgme_op_encrypt_result(ctx);
  if(!r || r->invalid_recipients || !cipher_ok)goto done;
 }
 if(status_failed || result.overflow || (op!=2 && !result.size))goto done;
 success=1;
done:
 if(success) {
  char hash_value[32];if(hash)snprintf(hash_value,sizeof(hash_value),"%u",hash);else strcpy(hash_value,"null");
  snprintf(metadata,sizeof(metadata),"{\"version\":1,\"ok\":true,\"operation\":\"%s\",\"signer_fingerprint\":%s%s%s,\"primary_fingerprint\":%s%s%s,\"signature\":\"%s\",\"hash_algorithm\":%s}",operation,*signer?"\"":"",*signer?signer:"null",*signer?"\"":"",*primary?"\"":"",*primary?primary:"null",*primary?"\"":"",op==2||op==3?"valid":"none",hash_value);
 } else snprintf(metadata,sizeof(metadata),"{\"version\":1,\"ok\":false,\"operation\":\"%s\",\"error\":\"%s\"}",operation,result.overflow?"limit":error);
 size_t size=strlen(metadata);int written=write_number((uint32_t)size)&&write_number(success?(uint32_t)result.size:0)&&fwrite(metadata,1,size,stdout)==size&&(!success||!result.size||fwrite(result.bytes,1,result.size,stdout)==result.size);
 if(output)gpgme_data_release(output);
 if(detached)gpgme_data_release(detached);
 if(input)gpgme_data_release(input);
 if(ctx)gpgme_release(ctx);
 for(unsigned i=0;i<KEY_LIMIT;i++)if(selected[i])gpgme_key_unref(selected[i]);
 if(content){memset(content,0,content_size);free(content);}if(signature){memset(signature,0,signature_size);free(signature);}if(result.bytes){memset(result.bytes,0,result.size);free(result.bytes);}
 return success&&written?0:1;
}

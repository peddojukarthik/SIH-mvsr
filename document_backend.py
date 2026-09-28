import os, base64, hashlib, mimetypes, secrets, uuid
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from supabase import create_client

load_dotenv()
SUPABASE_URL=os.environ['SUPABASE_URL']; SUPABASE_SERVICE_ROLE_KEY=os.environ['SUPABASE_SERVICE_ROLE_KEY']
DOCUMENT_BUCKET=os.getenv('DOCUMENT_BUCKET','documents'); PRIVATE_KEY_DIR=Path(os.getenv('PRIVATE_KEY_DIR','./private_keys'))
MAX_FILE_SIZE=50*1024*1024; SIGNED_URL_SECONDS=300
PRIVATE_KEY_DIR.mkdir(parents=True,exist_ok=True)
KEY_ENCRYPTION_KEY=os.getenv('KEY_ENCRYPTION_KEY')
if not KEY_ENCRYPTION_KEY: raise RuntimeError('KEY_ENCRYPTION_KEY missing. Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"')
fernet=Fernet(KEY_ENCRYPTION_KEY.encode())
supabase=create_client(SUPABASE_URL,SUPABASE_SERVICE_ROLE_KEY)
app=FastAPI(title='SIH Secure Document Backend')
app.add_middleware(CORSMiddleware,allow_origins=['*'],allow_credentials=False,allow_methods=['*'],allow_headers=['*'])
ALLOWED_EXTENSIONS={'.pdf','.png','.jpg','.jpeg','.doc','.docx','.ppt','.pptx','.txt'}
ALLOWED_DOCUMENT_TYPES={'fir','evidence','forensic_report','postmortem_report','witness_statement','charge_sheet','court_order','judgment'}
UPLOAD_PERMISSIONS={'upload','sign','grant'}

def parse_ts(v): return datetime.fromisoformat(v.replace('Z','+00:00'))
def sha256(b): return hashlib.sha256(b).hexdigest()
def private_path(uid): return PRIVATE_KEY_DIR/f'{uid}.key'
def filename_of(name):
    name=os.path.basename(name or '').strip().replace('/','_').replace('\\','_')
    if not name or name in {'.','..'}: raise HTTPException(400,'Invalid filename.')
    return ''.join(c for c in name if c.isprintable())
def file_type(ext):
    if ext in {'.png','.jpg','.jpeg'}: return 'image'
    if ext in {'.pdf','.doc','.docx','.ppt','.pptx','.txt'}: return 'text'
    raise HTTPException(400,'Unsupported file type.')

def current_user(auth):
    if not auth or not auth.startswith('Bearer '): raise HTTPException(401,'Not logged in. Include your session token.')
    raw=auth.removeprefix('Bearer ').strip()
    if not raw: raise HTTPException(401,'Missing session token.')
    th=hashlib.sha256(raw.encode()).hexdigest()
    s=supabase.table('sessions').select('session_id,user_id,expires_at').eq('token_hash',th).limit(1).execute()
    if not s.data: raise HTTPException(401,'Invalid session. Please log in again.')
    if datetime.now(timezone.utc)>parse_ts(s.data[0]['expires_at']): raise HTTPException(401,'Session expired. Please log in again.')
    u=supabase.table('users').select('user_id,employee_id,account_status,employee_registry!fk_users_employee(full_name,department_id,departments(type,name))').eq('user_id',s.data[0]['user_id']).limit(1).execute()
    if not u.data: raise HTTPException(401,'User not found.')
    x=u.data[0]; r=x.get('employee_registry') or {}; d=r.get('departments') or {}
    return {'user_id':x['user_id'],'employee_id':x.get('employee_id'),'full_name':r.get('full_name'),'department_id':r.get('department_id'),'department_type':d.get('type'),'department_name':d.get('name')}

def membership(uid,cid):
    r=supabase.table('case_membership').select('permission_level,expires_at,allowed_document_types').eq('user_id',uid).eq('case_id',cid).limit(1).execute()
    if not r.data: raise HTTPException(403,'You are not a member of this case.')
    x=r.data[0]
    if x.get('expires_at') and datetime.now(timezone.utc)>parse_ts(x['expires_at']): raise HTTPException(403,'Your case access has expired.')
    return x

def check_upload(uid,cid,dt):
    m=membership(uid,cid)
    if m['permission_level'] not in UPLOAD_PERMISSIONS: raise HTTPException(403,"You don't have upload permission for this case.")
    allowed=set(m.get('allowed_document_types') or [])
    if dt not in allowed: raise HTTPException(403,f"You are not authorized to upload '{dt}'. Your access covers: {sorted(allowed) or 'nothing'}.")
    return m

def ensure_key(uid):
    r=supabase.table('user_keys').select('key_id,public_key,kms_key_reference,algorithm,key_status').eq('user_id',uid).eq('key_status','active').limit(1).execute()
    if r.data:
        if not private_path(uid).exists(): raise HTTPException(500,"Active public key exists but encrypted private key is missing.")
        return r.data[0]
    private=ec.generate_private_key(ec.SECP256R1()); public=private.public_key()
    priv=private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()
    pub=public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    private_path(uid).write_bytes(fernet.encrypt(priv.encode()))
    try: os.chmod(private_path(uid),0o600)
    except OSError: pass
    r=supabase.table('user_keys').insert({'user_id':uid,'public_key':pub,'kms_key_reference':f'local-encrypted-key:{uid}','algorithm':'ECDSA-P256','key_status':'active'}).execute()
    if not r.data: raise HTTPException(500,'Could not create signing key record.')
    return r.data[0]

def sign(uid,h):
    pem=fernet.decrypt(private_path(uid).read_bytes()).decode(); k=serialization.load_pem_private_key(pem.encode(),password=None)
    return base64.b64encode(k.sign(h.encode(),ec.ECDSA(hashes.SHA256()))).decode()
def verify(pub,h,sig):
    try:
        k=serialization.load_pem_public_key(pub.encode()); k.verify(base64.b64decode(sig,validate=True),h.encode(),ec.ECDSA(hashes.SHA256())); return True
    except Exception: return False

def allowed_view(uid,cid,dt):
    m=membership(uid,cid); allowed=set(m.get('allowed_document_types') or [])
    if dt not in allowed: raise HTTPException(403,'You are not authorized to view this document.')

@app.get('/health')
def health(): return {'status':'ok'}

@app.get('/case/documents')
def case_documents(case_id:str,authorization:str|None=Header(default=None)):
    u=current_user(authorization); m=membership(u['user_id'],case_id); allowed=set(m.get('allowed_document_types') or [])
    r=supabase.table('documents').select('document_id,case_id,document_type,file_type,uploader_id,current_version_id,document_versions!fk_documents_current_version(version_id,storage_path,file_hash,signature,timestamp)').eq('case_id',case_id).execute()
    out=[]
    for d in r.data or []:
        if d['document_type'] not in allowed: continue
        v=d.get('document_versions') or {}; v=v[0] if isinstance(v,list) and v else (v if isinstance(v,dict) else {})
        p=v.get('storage_path')
        out.append({'document_id':d['document_id'],'document_type':d['document_type'],'file_type':d['file_type'],'uploader_id':d['uploader_id'],'current_version_id':d['current_version_id'],'filename':os.path.basename(p) if p else 'Unnamed file','file_hash':v.get('file_hash'),'signature':v.get('signature'),'timestamp':v.get('timestamp')})
    return {'my_permission_level':m['permission_level'],'my_allowed_document_types':sorted(allowed),'documents':out}

@app.post('/documents/upload')
async def upload_document(case_id:str=Form(...),document_type:str=Form(...),file:UploadFile=File(...),authorization:str|None=Header(default=None)):
    u=current_user(authorization); uid=u['user_id']; dt=document_type.strip().lower()
    try: uuid.UUID(case_id)
    except ValueError: raise HTTPException(400,'Invalid case ID.')
    if dt not in ALLOWED_DOCUMENT_TYPES: raise HTTPException(400,f'Invalid document type. Allowed: {sorted(ALLOWED_DOCUMENT_TYPES)}')
    check_upload(uid,case_id,dt)
    name=filename_of(file.filename); ext=Path(name).suffix.lower(); ft=file_type(ext); data=await file.read()
    if not data: raise HTTPException(400,'The selected file is empty.')
    if len(data)>MAX_FILE_SIZE: raise HTTPException(413,'File is larger than the 50 MB limit.')
    h=sha256(data); key=ensure_key(uid); sig=sign(uid,h); did=str(uuid.uuid4()); vid=str(uuid.uuid4()); path=f'{case_id}/{did}/{vid}/{name}'
    ctype=file.content_type or mimetypes.guess_type(name)[0] or 'application/octet-stream'
    try:
        supabase.storage.from_(DOCUMENT_BUCKET).upload(path,data,{'content-type':ctype,'upsert':False})
        dr=supabase.table('documents').insert({'document_id':did,'case_id':case_id,'document_type':dt,'file_type':ft,'uploader_id':uid}).execute()
        if not dr.data: raise RuntimeError('Could not create document row.')
        vr=supabase.table('document_versions').insert({'version_id':vid,'document_id':did,'storage_path':path,'file_hash':h,'previous_version_hash':None,'signature':sig,'co_signature':None,'uploader_id':uid,'timestamp':datetime.now(timezone.utc).isoformat()}).execute()
        if not vr.data: raise RuntimeError('Could not create document version row.')
        ur=supabase.table('documents').update({'current_version_id':vid}).eq('document_id',did).execute()
        if not ur.data: raise RuntimeError('Could not set current_version_id.')
    except Exception as exc:
        try: supabase.storage.from_(DOCUMENT_BUCKET).remove([path])
        except Exception: pass
        try: supabase.table('documents').delete().eq('document_id',did).execute()
        except Exception: pass
        raise HTTPException(500,f'Could not register document: {exc}') from exc
    return {'success':True,'message':'File uploaded and digitally signed.','document_id':did,'version_id':vid,'filename':name,'file_size':len(data),'file_type':ft,'document_type':dt,'file_hash':h,'hash_algorithm':'SHA-256','signature':sig,'signature_algorithm':'ECDSA-P256','storage_path':path,'public_key':key['public_key']}

@app.get('/documents/file/{version_id}')
def document_file(version_id:str,authorization:str|None=Header(default=None)):
    u=current_user(authorization); vr=supabase.table('document_versions').select('version_id,document_id,storage_path').eq('version_id',version_id).limit(1).execute()
    if not vr.data: raise HTTPException(404,'Document version not found.')
    v=vr.data[0]; dr=supabase.table('documents').select('document_id,case_id,document_type').eq('document_id',v['document_id']).limit(1).execute()
    if not dr.data: raise HTTPException(404,'Document not found.')
    d=dr.data[0]; allowed_view(u['user_id'],d['case_id'],d['document_type'])
    try:
        s=supabase.storage.from_(DOCUMENT_BUCKET).create_signed_url(v['storage_path'],SIGNED_URL_SECONDS)
        url=s.get('signedURL') or s.get('signedUrl') or s.get('signed_url')
        if not url: raise RuntimeError(f'No signed URL returned: {s}')
        return {'url':url,'expires_in':SIGNED_URL_SECONDS}
    except Exception as exc: raise HTTPException(500,f'Could not create secure file URL: {exc}') from exc

@app.get('/documents/verify/{version_id}')
def verify_document(version_id:str,authorization:str|None=Header(default=None)):
    u=current_user(authorization); vr=supabase.table('document_versions').select('version_id,document_id,storage_path,file_hash,signature,uploader_id').eq('version_id',version_id).limit(1).execute()
    if not vr.data: raise HTTPException(404,'Document version not found.')
    v=vr.data[0]; dr=supabase.table('documents').select('document_id,case_id,document_type').eq('document_id',v['document_id']).limit(1).execute()
    if not dr.data: raise HTTPException(404,'Document not found.')
    d=dr.data[0]; allowed_view(u['user_id'],d['case_id'],d['document_type'])
    try: stored=supabase.storage.from_(DOCUMENT_BUCKET).download(v['storage_path'])
    except Exception as exc: raise HTTPException(500,f'Could not retrieve file: {exc}') from exc
    actual=sha256(stored); hash_ok=secrets.compare_digest(actual,v['file_hash'])
    kr=supabase.table('user_keys').select('public_key').eq('user_id',v['uploader_id']).eq('key_status','active').limit(1).execute()
    if not kr.data: raise HTTPException(404,'Uploader public key not found.')
    sig_ok=verify(kr.data[0]['public_key'],v['file_hash'],v['signature'])
    return {'valid':bool(hash_ok and sig_ok),'hash_matches':hash_ok,'signature_valid':sig_ok,'stored_hash':v['file_hash'],'actual_hash':actual,'algorithm':'ECDSA-P256 + SHA-256','version_id':version_id,'uploader_id':v['uploader_id']}

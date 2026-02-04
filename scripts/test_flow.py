import requests, time

base='http://127.0.0.1:5000'
s = requests.Session()
# wait a bit for server to be ready
for i in range(6):
    try:
        r = s.get(base + '/');
        break
    except Exception as e:
        time.sleep(1)

print('Creating user...')
r = requests.post(base + '/users', json={'username':'tester','password':'Str0ngPass!2025','role':'user'})
print('create user:', r.status_code, r.text)

print('Logging in...')
r = s.post(base + '/login', data={'username':'tester','password':'Str0ngPass!2025'})
print('login status:', r.status_code)

print('Uploading file...')
files = {'file': ('hello.txt', b'hello world')}
r = s.post(base + '/upload', files=files, allow_redirects=True)
print('upload status:', r.status_code, 'url:', getattr(r, 'url', ''))

print('Listing files...')
r = s.get(base + '/files')
print('files status:', r.status_code)
print(r.text[:1000])

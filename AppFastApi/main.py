import os
import shutil
import pycades
import base64
import json
import filecmp
import pathlib
import uvicorn
from pycryptoprosdk import CryptoProSDK
from typing import Optional
from fastapi import \
    FastAPI,\
    File,\
    UploadFile
from fastapi.responses import \
    JSONResponse, \
    RedirectResponse
from certificate.finder import \
    store_data, \
    signature_data, \
    signature_data_pin
from certificate.info import certificate_info

app = FastAPI()
sdk = CryptoProSDK()

async def write_file(save_file, data_file):
    with open(save_file, 'wb') as buffer:
        shutil.copyfileobj(data_file.file, buffer)


@app.get('/', deprecated=True)
async def redirect_page_docs():
    return RedirectResponse('/docs#/')


@app.get('/certificates')
async def data_certificates():
    """
    Получает список сертификатов
    """
    ret = {}
    certificate = await store_data()
    for i in range(1, certificate.Count+1):
        ret[f'certificate_{i}'] = await certificate_info(certificate.Item(i))
    return JSONResponse(content={'data_certificates': ret})


@app.get('/root_certificates')
async def data_root_certificates():
    """
    Получения списка корневых сертификатов
    """
    ret = {}
    certificate = await store_data(pycades.CAPICOM_ROOT_STORE)
    for i in range(1, certificate.Count+1):
        ret[f'certificate_{i}'] = await certificate_info(certificate.Item(i))
    return JSONResponse(content={'data_certificates': ret})

@app.get('/info')
async def app_info():
    pycades_version = pycades.ModuleVersion()
    return {'pycades_version': pycades_version}

@app.post('/certificate/root')
async def root_certificates(file: UploadFile = File(...)):
    """
    Установка корневого сертификата в формате cer, crt
    """
    # TODO: запрещать пробелы и спецсимволы
    if pathlib.Path(file.filename).suffix in ('.p7b', '.cer', '.crt'):
        root_certificate = os.path.join('/static', file.filename)
        await write_file(root_certificate, file)
        os.system(f'cat {root_certificate}  | /scripts/root')
        os.remove(root_certificate)
        return JSONResponse(content={'status': 'Root certificate installed'})
    else:
        return JSONResponse(content={'error': 'Invalid file format. Desired format <*.p7b> or <*.cer>'})


@app.post('/certificate/private_key', deprecated=True)
async def private_key(file: UploadFile = File(..., description="Файл в виде zip архива"), pin: Optional[str] = None):

    if pathlib.Path(file.filename).suffix == '.zip':
        user_certificate = os.path.join('/static', file.filename)
        await write_file(user_certificate, file)
        if pin:
            os.system(f'cat {user_certificate} | /scripts/my {pin}')
        else:
            result = os.system(f'cat {user_certificate} | /scripts/my')
        os.remove(user_certificate)
        return JSONResponse(content={'status': 'Private key installed'})
    else:
        return JSONResponse(content={'error': 'Invalid file format. Desired format <*.zip>'})

@app.post('/certificate/private_key_pfx')
async def private_key_pfx(file: UploadFile = File(..., description="Файл в виде zip архива")):
    """
    Установка сертификата и приватного ключа из pfx файла
    """
    if pathlib.Path(file.filename).suffix == '.pfx':
        user_certificate = os.path.join('/static', file.filename)
        await write_file(user_certificate, file)
        result = os.system(f'cat {user_certificate} | /scripts/my_pfx')
        os.remove(user_certificate)
        return JSONResponse(content={'status': 'Private key installed'})
    else:
        return JSONResponse(content={'error': 'Invalid file format. Desired format <*.zip>'})

@app.post('/license')
async def license_number(serial_number: str):
    os.system(f'cpconfig -license -set {serial_number}')
    return JSONResponse(content={'statusLicense': 'Serial number license installed'})


@app.post('/signer', deprecated=True)
async def signer_file(file: UploadFile = File(...), pin: Optional[str] = None):
    if pin:
        signer = await signature_data_pin(pin)
    else:
        signer = await signature_data()
    signed_data = pycades.SignedData()
    signed_data.Content = base64.b64encode(await file.read()).decode()
    # убираем переносы
    signature = signed_data.SignCades(signer, pycades.CADESCOM_CADES_BES).replace("\r\n", "")
    return JSONResponse(content={'signedContent': signature,
                                 'filename': f'{file.filename}.sig'
                                 })
@app.post('/sign/{thumbprint}')
async def signer_file(thumbprint: str, file: UploadFile = File(...), detached: bool = False):

    data = await file.read()
    result = sdk.sign(message=data, thumbprint=thumbprint, detached=detached)
    # убираем переносы
    return JSONResponse(content={'signedContent': result.replace("\n", ""),
                                 'filename': f'{file.filename}.sig'
                                 })


@app.post('/unsigner', deprecated=True)
async def unsigner_file(file: UploadFile = File(...)):
    _signedData = pycades.SignedData()
    _signedData.VerifyCades((await file.read()).decode(), pycades.CADESCOM_CADES_BES)
    return JSONResponse(content={'unsignedContent': _signedData.Content,
                                 'filename': f"{file.filename.replace('.sig', '')}"
                                 })


@app.post('/verify', deprecated=True)
async def verified_file(original_file: UploadFile = File(...), signed_file: UploadFile = File(...)):
    tmp_original = os.path.join('/static', original_file.filename)
    tmp_signed = os.path.join('/static', signed_file.filename)
    await write_file(tmp_original, original_file)
    with open(tmp_signed, 'wb') as buffer:
        buffer.write(base64.b64decode(json.loads((await unsigner_file(signed_file)).body)['unsignedContent']))
    if filecmp.cmp(tmp_original, tmp_signed):
        subject_name = (await signature_data()).Certificate.SubjectName
    else:
        subject_name = 'Error (Maybe the file is signed with a different signature)'
    os.remove(tmp_original)
    os.remove(tmp_signed)
    return JSONResponse(content={'verifyContent': subject_name})


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", reload=True, port=8095)

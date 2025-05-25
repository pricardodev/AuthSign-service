import os
import base64
import tempfile
import shutil
from io import BytesIO
from pyhanko.sign import signers, fields
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils import misc
from pyhanko.pdf_utils.generic import DictionaryObject, NameObject, ArrayObject, Reference, IndirectObject, TextStringObject, StreamObject
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument
from asn1crypto import cms
from datetime import datetime
from pyhanko.pdf_utils.content import PdfContent
from pyhanko.stamp import TextStampStyle, TextBoxStyle, QRStampStyle

# Configurações padrão (nomes dos arquivos)
PDF_FILE = "sample.pdf"
SIGNATURE_FILE = "cms.p7s"
OUTPUT_FILE = "signed_sample.pdf"

def cmsDecode(cms_file_path):
    """Decodifica o arquivo CMS (.p7s) para o formato necessário."""
    try:
        with open(cms_file_path, 'rb') as f:
            cms_data = f.read()
        
        # Verificar se está em formato base64
        if cms_data.startswith(b'-----'):
            # Remover cabeçalhos e rodapés PEM
            cms_lines = cms_data.decode('utf-8').split('\n')
            cms_base64 = ''.join(line for line in cms_lines if not line.startswith('-----'))
            cms_data = base64.b64decode(cms_base64)
        
        return cms.ContentInfo.load(cms_data)
    except Exception as e:
        raise ValueError(f"Erro ao decodificar a assinatura CMS: {str(e)}")

# Função para extrair informações do CMS
def extract_cms_info(cms_content):
    try:
        print("Extraindo informações do CMS...")
        # Acessar certificados
        certificates = cms_content['content']['certificates']
        if not certificates:
            print("ERRO: Nenhum certificado encontrado em cms_content['content']['certificates']")
            return "Desconhecido", datetime.now()
        
        # Extrair informações do primeiro certificado
        subject_str = "Desconhecido"

        print(f"Número de certificados encontrados: {len(certificates)}")
        for cert_data in certificates:
            try:
                subject_str = cert_data.native['tbs_certificate']['subject']['common_name']

                break  # Usar o primeiro certificado por padrão
            except Exception as e:
                print(f"Erro ao carregar certificado: {e}")

        # Acessar signer_infos para o signing_time
        if 'signer_infos' not in cms_content['content']:
            print("ERRO: cms_content não contém signer_infos")
            return subject_str, datetime.now()
        signer_info = cms_content['content']['signer_infos'][0]
        # print(f"Signer info: {signer_info.native}")

        # Extrair timestamp
        timestamp = None
        signed_attrs = signer_info['signed_attrs']
        # print(f"Signed attributes: {[attr.native for attr in signed_attrs]}")
        for attr in signed_attrs:
            if attr['type'].native == 'signing_time':
                timestamp = attr['values'][0].native
                print(f"Timestamp encontrado: {timestamp}")
                break
        if not timestamp:
            print("AVISO: signing_time não encontrado, usando data atual")
            timestamp = datetime.now()

        return subject_str, timestamp
    except Exception as e:
        print(f"Erro geral ao extrair informações do CMS: {e}")
        return "Desconhecido", datetime.now()

# Função auxiliar para inspecionar objetos
def inspect_object(obj, name):
    print(f"Inspecionando {name}: tipo={type(obj)}, valor={obj}")
    if isinstance(obj, (Reference, IndirectObject)):
        try:
            resolved = obj.get_object()
            print(f"{name} resolvido: tipo={type(resolved)}, valor={resolved}")
            return resolved
        except Exception as e:
            print(f"Erro ao resolver {name}: {e}")
    elif isinstance(obj, (DictionaryObject, ArrayObject)):
        print(f"{name} é um {type(obj).__name__}")
    elif isinstance(obj, int):
        print(f"ERRO: {name} é um inteiro ({obj}), isso pode causar o erro 'write_to_stream'")
    else:
        print(f"{name} é de tipo inesperado: {type(obj)}")
    return obj

def prepare_pdf(pdf_path):
    """Prepara um documento PDF para assinatura, criando um arquivo temporário e retornando o digest."""
    try:
        print(f"Preparando arquivo PDF: {pdf_path}")
        
        # Abrir o arquivo PDF
        with open(pdf_path, 'rb') as f:
            original = f.read()
            print(f"Tamanho do PDF original: {len(original)} bytes")
        
        # Criar um buffer para o PDF
        with open(pdf_path, 'rb') as f:
            w = IncrementalPdfFileWriter(f)
            print("IncrementalPdfFileWriter inicializado")

            # Configurar a aparência
            stamp_text = (
                "Documento Assinado Digitalmente\n"
                # "Assinante: %(signer)s\n"
                "Data/Hora: %(ts)s\n"
                # "Local: %(location)s\n"
                # "Motivo: %(reason)s"
            )
            
            stamp_style = QRStampStyle(
                stamp_text=stamp_text,
                text_box_style=TextBoxStyle(
                    font_size=16,
                    # leading=14,  # Espaçamento entre linhas
                    # border_width=1,
                ),
                qr_inner_size=100
                # background=None,
            )
            # stamp_style = TextStampStyle(
            #     stamp_text=stamp_text,
            #     text_box_style=TextBoxStyle(
            #         font_size=12,
            #         # leading=14,  # Espaçamento entre linhas
            #         # border_width=1,
            #     ),
            #     # background=None,
            # )
            print(f"TextStampStyle configurado: {stamp_text}")

            
            # Configurar o campo de assinatura
            sig_field_spec = fields.SigFieldSpec(
                sig_field_name='Signature',
                on_page=0,  # Primeira página
                # Posição do campo de assinatura (x1, y1, x2, y2)
                box=(325, 25, 550, 80)  # Canto inferior direito
            )
            
            # Adicionar o campo de assinatura ao PDF
            fields.append_signature_field(w, sig_field_spec)
            print("Campo de assinatura adicionado ao PDF")
            
            # Configurar o assinante com o stamp
            pdf_signer = signers.PdfSigner(
                signature_meta=signers.PdfSignatureMetadata(
                    field_name='Signature',
                    md_algorithm='sha256',
                    reason="Assinatura"
                ),
                signer=signers.ExternalSigner(
                    signing_cert=None,
                    cert_registry=None,
                    signature_value=16384,  # Espaço reservado para a assinatura CMS
                ),
                stamp_style=stamp_style,  # Aplicar o stamp configurado
                new_field_spec=sig_field_spec,  # Usar o campo criado
            )

            # Configurar o assinante
            # pdf_signer = signers.PdfSigner(
            #     signature_meta=signers.PdfSignatureMetadata(
            #         field_name='Signature',
            #         md_algorithm='sha256',
            #     ),
            #     signer=signers.ExternalSigner(
            #         signing_cert=None,
            #         cert_registry=None,
            #         signature_value=16384,  # Tamanho suficiente para CMS
            #     ),
            #     stamp_style=stamp_style
            # )


            print("PdfSigner configurado com ExternalSigner (signature_value=16384)")

            # Preparar o documento
            output = BytesIO()
            prep_digest, tbs_document, output = pdf_signer.digest_doc_for_signing(
                w, bytes_reserved=16384, output=output,
                appearance_text_params = {
                    'url': 'https://validar.iti.gov.br/'
                }
            )
            print(f"Digest preparado: {prep_digest.document_digest.hex()}")

        prepared_pdf = output.getvalue()
        print(f"Tamanho do PDF preparado: {len(prepared_pdf)} bytes")

        if len(prepared_pdf) == len(original):
            print("AVISO: O PDF preparado é idêntico ao PDF original! Nenhuma alteração detectada.")
        else:
            print("Sucesso: O PDF preparado foi modificado em relação ao original.")

        # Salvar o documento preparado para visualização
        prepared_pdf_path = "prepared_" + os.path.basename(pdf_path)
        with open(prepared_pdf_path, "wb") as f:
            output.seek(0)
            f.write(output.read())
        print(f"PDF preparado salvo em {prepared_pdf_path}")

        return prep_digest, output, prepared_pdf_path
        
    except Exception as e:
        print(f"Erro ao preparar o documento: {str(e)}")
        raise

def embed_signature(prep_digest, output, signature_path, output_path):
    """Incorpora a assinatura CMS no documento PDF preparado."""
    try:
        print(f"Incorporando assinatura do arquivo: {signature_path}")
        
        # Decodificar a assinatura CMS
        cms_content = cmsDecode(signature_path)
        
        # Verificar tamanho da assinatura
        with open(signature_path, 'rb') as f:
            cms_signature = f.read()
        print(f"Tamanho do arquivo .p7s: {len(cms_signature)} bytes")
        if len(cms_signature) > 16384:
            raise ValueError('Arquivo .p7s excede o tamanho reservado (16384 bytes)')
        
        # Incorporar a assinatura
        output.seek(0)
        print(f"Tamanho do output antes de finish_signing: {len(output.read())} bytes")
        output.seek(0)
        
        result = PdfTBSDocument.finish_signing(
            output=output,
            prepared_digest=prep_digest,
            signature_cms=cms_content
        )
        print(f"Resultado de finish_signing: {result}")
        
        # Salvar o PDF assinado
        output.seek(0)
        signed_pdf = output.read()
        with open(output_path, "wb") as f:
            f.write(signed_pdf)
        print(f"PDF assinado salvo em {output_path}")

        return output_path
        
    except Exception as e:
        print(f"Erro ao incorporar a assinatura: {str(e)}")
        raise





def main():
    # Verificar se os arquivos existem
    if not os.path.exists(PDF_FILE):
        print(f"Erro: Arquivo PDF não encontrado: {PDF_FILE}")
        return
    
    if not os.path.exists(SIGNATURE_FILE):
        print(f"Erro: Arquivo de assinatura não encontrado: {SIGNATURE_FILE}")
        return
    
    try:
        # Preparar o PDF
        prep_digest, output, prepared_path = prepare_pdf(PDF_FILE)
        
        # Incorporar a assinatura
        signed_path = embed_signature(prep_digest, output, SIGNATURE_FILE, OUTPUT_FILE)
        
        print(f"\nProcesso concluído com sucesso!")
        print(f"Arquivo original: {PDF_FILE}")
        print(f"Arquivo preparado: {prepared_path}")
        print(f"Arquivo assinado: {signed_path}")
        
    except Exception as e:
        print(f"Erro durante o processo: {e}")

if __name__ == '__main__':
    main()

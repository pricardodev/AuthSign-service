from flask import Flask, request, jsonify
import tempfile
import os
import base64
import shutil
from pyhanko.sign import signers, fields
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
# from pyhanko.pdf_utils import misc
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument
# from io import BytesIO
from pyhanko.stamp import TextStampStyle, QRStampStyle, TextBoxStyle

app = Flask(__name__)

# Armazenamento temporário dos documentos em preparação
tbs_documents = {}

def cmsDecode(cms_in_base64_pkcs7: str):
    from asn1crypto import cms
    cms_lines = cms_in_base64_pkcs7.split('\n')
    cms_base64 = ''.join(line for line in cms_lines if not line.startswith('-----'))

    try:
        cms_data = base64.b64decode(cms_base64)
        
        return cms.ContentInfo.load(cms_data)
    except Exception as e:
        raise ValueError(f"Erro ao decodificar a assinatura CMS: {str(e)}")

@app.route('/prepare-pdf-document', methods=['POST'])
def prepare_pdf():
    """Prepara um documento PDF para assinatura, retornando o digest e um ID."""
    try:
        # Verificar se o arquivo foi enviado
        if 'file' not in request.files:
            return jsonify({'error': 'Nenhum arquivo enviado'}), 400
        
        pdf_file = request.files['file']
        if not pdf_file.filename.endswith('.pdf'):
            return jsonify({'error': 'Arquivo deve ser um PDF'}), 400

        # Criar um buffer para o PDF
        w = IncrementalPdfFileWriter(pdf_file.stream)

        stamp_text = (
            "Documento Assinado Digitalmente\n"
            # "Assinante: %(signer)s\n"
            "Data/Hora: %(ts)s\n"
        )
        
        stamp_style = QRStampStyle(
            stamp_text=stamp_text,
            text_box_style=TextBoxStyle(
                font_size=16,
            ),
            qr_inner_size=100
        )
        
        # Configurar o campo de assinatura
        sig_field_spec = fields.SigFieldSpec(
            sig_field_name='Signature',
            on_page=0,  # Primeira página
            # Posição do campo de assinatura (x1, y1, x2, y2)
            box=(325, 25, 550, 80)  # Canto inferior direito
        )
        
        # Adicionar o campo de assinatura ao PDF
        fields.append_signature_field(w, sig_field_spec)
        
        # Configurar o assinante com o stamp
        pdf_signer = signers.PdfSigner(
            signature_meta=signers.PdfSignatureMetadata(
                field_name='Signature',
                md_algorithm='sha256',
            ),
            signer=signers.ExternalSigner(
                signing_cert=None,
                cert_registry=None,
                signature_value=16384,  # Espaço reservado para a assinatura CMS
            ),
            stamp_style=stamp_style,  # Aplicar o stamp configurado
            new_field_spec=sig_field_spec,  # Usar o campo criado
        )

        # Preparar o documento
        prep_digest, tbs_document, output = pdf_signer.digest_doc_for_signing(
            w, bytes_reserved=16384
        )

        # Gerar um ID único para o documento
        doc_id = os.urandom(16).hex()

        # Criar um diretório temporário para armazenar o buffer
        temp_dir = tempfile.mkdtemp()

        # Armazenar os dados no tbs_documents
        output.seek(0)
        tbs_documents[doc_id] = {
            'prep_digest': prep_digest,
            'output': output,
            'temp_dir': temp_dir
        }
        
        return jsonify({
            'doc_id': doc_id,
            'hash': prep_digest.document_digest.hex()
        })
    except Exception as e:
        print(f"Erro ao preparar o documento: {str(e)}")
        return jsonify({'error': f"Erro ao preparar o documento: {str(e)}"}), 500


@app.route('/embed-cms-in-prepered-document', methods=['POST'])
def embed_signature_in_previous_prepered_document():
    """Incorpora a assinatura CMS (arquivo .p7s) no documento PDF, adiciona o campo visual e retorna o PDF assinado."""
    try:
        # Validar entrada
        if 'doc_id' not in request.form or 'signature' not in request.files:
            return jsonify({'error': 'Dados incompletos: doc_id e arquivo de assinatura (.p7s) são obrigatórios'}), 400

        doc_id = request.form['doc_id']
        signature_file = request.files['signature']

        # Validar extensão do arquivo
        if not signature_file.filename.endswith('.p7s'):
            return jsonify({'error': 'O arquivo de assinatura deve ter extensão .p7s'}), 400

        if doc_id not in tbs_documents:
            return jsonify({'error': 'Documento não encontrado'}), 404

        # Recuperar dados do documento
        doc_data = tbs_documents[doc_id]
        prep_digest = doc_data['prep_digest']
        output = doc_data['output']
        temp_dir = doc_data['temp_dir']

        # Ler a assinatura CMS do arquivo .p7s
        cms_signature = signature_file.read()
        cms_content = cmsDecode(cms_signature.decode('utf-8'))
        if len(cms_signature) > 16384:
            return jsonify({'error': 'Arquivo .p7s excede o tamanho reservado (16384 bytes)'}), 400

        # Incorporar a assinatura
        result = PdfTBSDocument.finish_signing(
            output=output,
            prepared_digest=prep_digest,
            signature_cms=cms_content
        )

        output.seek(0)

        # Retornar o PDF assinado codificado em Base64
        return jsonify({
            'signed_pdf': base64.b64encode(output.read()).decode('ascii')
        })
    except ValueError as e:
        print(f"Erro ao incorporar a assinatura: {str(e)}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        print(f"Erro ao incorporar a assinatura: {str(e)}")
        return jsonify({'error': f"Erro ao incorporar a assinatura: {str(e)}"}), 500
    finally:
        # Limpar recursos
        shutil.rmtree(temp_dir, ignore_errors=True)
        del tbs_documents[doc_id]


if __name__ == '__main__':
    app.run(host='localhost', port=5000, debug=True)
       
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
from pyhanko.stamp import TextStampStyle, TextBoxStyle

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

@app.route('/prepare-document', methods=['POST'])
def prepare_pdf():
    """Prepara um documento PDF para assinatura, retornando o digest e um ID."""
    try:
        # Verificar se o arquivo foi enviado
        if 'file' not in request.files:
            return jsonify({'error': 'Nenhum arquivo enviado'}), 400
        
        pdf_file = request.files['file']
        if not pdf_file.filename.endswith('.pdf'):
            return jsonify({'error': 'Arquivo deve ser um PDF'}), 400

        print(f"Arquivo PDF recebido: {pdf_file.filename}")

        # Criar um buffer para o PDF
        original = pdf_file.read()
        print(f"Tamanho do PDF original: {len(original)} bytes")

        w = IncrementalPdfFileWriter(pdf_file.stream)
        print("IncrementalPdfFileWriter inicializado")

        # Configurar a aparência com TextStampStyle
        stamp_text = (
            "Assinatura Digital\n"
            "Assinante: {signer}\n"
            "Data/Hora: {timestamp}"
        ).format(signer="Assinante", timestamp="Data/Hora")
        stamp_style = TextStampStyle(
            # stamp_text=stamp_text,
            text_box_style=TextBoxStyle(
                font_size=12,
                leading=14,  # Espaçamento entre linhas
                border_width=1,
            ),
            # background=None,
        )
        print(f"TextStampStyle configurado: {stamp_text}")

        
        # Configurar o campo de assinatura
        sig_field_spec = fields.SigFieldSpec(
            sig_field_name='Signature',
            on_page=0,  # Primeira página
            # Posição do campo de assinatura (x1, y1, x2, y2)
            box=(400, 50, 550, 130)  # Canto inferior direito
        )
        
        # Adicionar o campo de assinatura ao PDF
        fields.append_signature_field(w, sig_field_spec)
        print("Campo de assinatura adicionado ao PDF")
        
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
            new_field_spec=sig_field_spec  # Usar o campo criado
        )

        # Configurar o assinante
        pdf_signer = signers.PdfSigner(
            signers.PdfSignatureMetadata(
                field_name='Signature',
                md_algorithm='sha256',
            ),
            signer=signers.ExternalSigner(
                signing_cert=None,
                cert_registry=None,
                signature_value=16384,  # Tamanho suficiente para CMS
            )
        )
        print("PdfSigner configurado com ExternalSigner (signature_value=16384)")

        # Preparar o documento
        prep_digest, tbs_document, output = pdf_signer.digest_doc_for_signing(
            w, bytes_reserved=16384
        )
        print(f"Digest preparado: {prep_digest.document_digest.hex()}")
        print(f"Objeto prep_digest: {prep_digest}")
        print(f"Objeto tbs_document: {tbs_document}")
        print(f"Objeto output: {output}")
        print("Documento preparado (PdfTBSDocument) criado")


        prepared_pdf = output.read()
        print(f"Tamanho do PDF preparado: {len(prepared_pdf)} bytes")


        if len(prepared_pdf) == len(original):
            print("AVISO: O PDF preparado é idêntico ao PDF original! Nenhuma alteração detectada.")
        else:
            print("Sucesso: O PDF preparado foi modificado em relação ao original.")

        # Salvar o documento preparado para depuração
        output.seek(0)
        with open("debug_prepared.pdf", "wb") as f:
            f.write(output.read())
        print("PDF preparado salvo em debug_prepared.pdf")

        # Gerar um ID único para o documento
        doc_id = os.urandom(16).hex()
        print(f"ID do documento gerado: {doc_id}")

        # Criar um diretório temporário para armazenar o buffer
        temp_dir = tempfile.mkdtemp()
        print(f"Diretório temporário criado: {temp_dir}")

        # Armazenar os dados no tbs_documents
        output.seek(0)
        tbs_documents[doc_id] = {
            'prep_digest': prep_digest,
            'output': output,
            'temp_dir': temp_dir
        }
        print(f"Documento armazenado em tbs_documents com doc_id: {doc_id}")
        
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

        print("-----------EMBED------------")

        # Recuperar dados do documento
        doc_data = tbs_documents[doc_id]
        prep_digest = doc_data['prep_digest']
        output = doc_data['output']
        temp_dir = doc_data['temp_dir']

        # Ler a assinatura CMS do arquivo .p7s
        cms_signature = signature_file.read()
        cms_content = cmsDecode(cms_signature.decode('utf-8'))
        print(f"Tamanho do arquivo .p7s: {len(cms_signature)} bytes")
        if len(cms_signature) > 16384:
            return jsonify({'error': 'Arquivo .p7s excede o tamanho reservado (16384 bytes)'}), 400


        output.seek(0)
        print(f"Tamanho do output antes de finish_signing: {len(output.read())} bytes")
        output.seek(0)

        # Incorporar a assinatura
        
        result = PdfTBSDocument.finish_signing(
            output=output,
            prepared_digest=prep_digest,
            signature_cms=cms_content
        )
        print(f"Resultado de finish_signing: {result}")

        output.seek(0)
        print(f"Tamanho do output após finish_signing: {len(output.read())} bytes")
        output.seek(0)

        # Criar um novo buffer para o PDF assinado
        output.seek(0)  # Garantir que o buffer está na posição inicial
        print(f"Tamanho do PDF assinado (antes da widget): {len(output.read())} bytes")
        output.seek(0)

        # Salvar o PDF Sem Widget para depuração
        with open("debug_signed_without_widget.pdf", "wb") as f:
            f.write(output.read())
        print("PDF assinado sem widget em debug_signed_without_widget.pdf")
        output.seek(0)

        # # Reabrir o PDF assinado para adicionar a widget visível
        # widget_buf = BytesIO(signed_pdf)
        # w = IncrementalPdfFileWriter(widget_buf)

        # # Localizar o campo de assinatura existente
        # sig_field = None
        # for field_name, field in fields.enumerate_sig_fields(w):
        #     if field_name == 'Signature':
        #         sig_field = field
        #         break

        # if not sig_field:
        #     return jsonify({'error': 'Campo de assinatura "Signature" não encontrado no PDF assinado'}), 500

        # # Adicionar a widget annotation ao campo existente
        # page = w.get_page(-1)  # Primeira página
        # annot = misc.PdfDict(
        #     Type=misc.PdfName('Annot'),
        #     Subtype=misc.PdfName('Widget'),
        #     Rect=[50, 50, 150, 100],  # Retângulo de 100x50 pontos
        #     FT=misc.PdfName('Sig'),
        #     T='Signature',
        #     P=page.ref
        # )
        # w.add_annot(annot, page_ref=page.ref)
        # sig_field.Kids = sig_field.get('Kids', []) + [annot]
        # print("Widget visível adicionado ao campo 'Signature' existente")

        # Forçar a gravação do PDF com a widget
        # final_buf = BytesIO()
        # w.write(final_buf)
        # final_buf.seek(0)
        # final_pdf = final_buf.read()
        # print(f"Tamanho do PDF final (com widget): {len(final_pdf)} bytes")

        # # Salvar o PDF final para depuração
        # with open("debug_signed.pdf", "wb") as f:
        #     f.write(final_pdf)
        # print("PDF assinado com widget salvo em debug_signed.pdf")

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

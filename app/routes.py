from flask import render_template, request
from app import app
from app.utils import check_spoof, predict_spoof_using_model, load_model, check_dmarc

model = load_model('model.pkl')

@app.route('/', methods=['GET', 'POST'])
def index():
    spoof_header = None
    spoof_content = None
    dmarc_result = None

    if request.method == 'POST':
        from_email = request.form.get('from_email', '')
        reply_to_email = request.form.get('reply_to_email', '')
        return_path_email = request.form.get('return_path_email', '')
        email_content = request.form.get('email_content', '')

        headers = {
            'From': from_email,
            'Reply-To': reply_to_email,
            'Return-Path': return_path_email
        }

        spoof_header = check_spoof(headers)
        spoof_content = predict_spoof_using_model(email_content, model)
        domain = from_email.split('@')[-1] if '@' in from_email else ''
        dmarc_result = check_dmarc(domain) if domain else 'Invalid Domain'

        return render_template(
            'index.html',
            spoof_header=spoof_header,
            spoof_content=spoof_content,
            dmarc_result=dmarc_result,
            form=request.form
        )

    return render_template(
        'index.html',
        spoof_header=None,
        spoof_content=None,
        dmarc_result=None,
        form={}
    )

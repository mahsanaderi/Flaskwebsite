from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user
from __init__ import db
import json
import finnhub
views = Blueprint('views', __name__)

finnhub_client = finnhub.Client(api_key="cmd9ra1r01qip5t7i7o0cmd9ra1r01qip5t7i7og")





@views.route("/about")
def about():
    return render_template("about.html",user=current_user)


@views.route('/', methods=['GET', 'POST'])
@login_required

def home():
    try:
        news = finnhub_client.general_news('general', min_id=0)
        return render_template('home.html', news=news,user=current_user)
    except Exception as e:
        return render_template('home.html',user=current_user)

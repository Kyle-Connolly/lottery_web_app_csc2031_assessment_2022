# IMPORTS
import logging

from cryptography.fernet import Fernet
from flask import Blueprint, render_template, request, flash
from flask_login import current_user
from sqlalchemy.orm import make_transient

from app import db
from models import Draw

# CONFIG
from users.views import requires_roles

lottery_blueprint = Blueprint('lottery', __name__, template_folder='templates')


# VIEWS
# view lottery page
@lottery_blueprint.route('/lottery')
@requires_roles('user')  # user access only
def lottery():
    return render_template('lottery/lottery.html')


@lottery_blueprint.route('/add_draw', methods=['POST'])
@requires_roles('user')  # user access only
def add_draw():
    submitted_draw = ''
    for i in range(6):
        submitted_draw += request.form.get('no' + str(i + 1)) + ' '
    submitted_draw.strip()

    # create a new draw with the form data.
    new_draw = Draw(user_id=current_user.id, numbers=submitted_draw, master_draw=False,
                    lottery_round=0, lottokey=current_user.lottokey)  # TODO: update user_id [user_id=1 is a placeholder]

    # add the new draw to the database
    db.session.add(new_draw)
    db.session.commit()

    # re-render lottery.page
    flash('Draw %s submitted.' % submitted_draw)
    return lottery()


# view all draws that have not been played
@lottery_blueprint.route('/view_draws', methods=['POST'])
@requires_roles('user')  # user access only
def view_draws():
    # get all draws that have not been played [played=0]
    playable_draws = Draw.query.filter_by(been_played=False, user_id=current_user.id).all()  # TODO: filter playable draws for current user

    # if playable draws exist
    if len(playable_draws) != 0:
        for draw in playable_draws:
            make_transient(draw)
            draw.view_numbers(current_user.lottokey)
        # re-render lottery page with playable draws
        return render_template('lottery/lottery.html', playable_draws=playable_draws)
    else:
        flash('No playable draws.')
        return lottery()


# view lottery results
@lottery_blueprint.route('/check_draws', methods=['POST'])
@requires_roles('user')  # user access only
def check_draws():
    # get played draws
    played_draws = Draw.query.filter_by(been_played=True, user_id=current_user.id).all()  # TODO: filter played draws for current user

    # if played draws exist
    if len(played_draws) != 0:
        return render_template('lottery/lottery.html', results=played_draws, played=True)

    # if no played draws exist [all draw entries have been played therefore wait for next lottery round]
    else:
        flash("Next round of lottery yet to play. Check you have playable draws.")
        return lottery()


# delete all played draws
@lottery_blueprint.route('/play_again', methods=['POST'])
@requires_roles('user')  # user access only
def play_again():
    Draw.query.filter_by(been_played=True, master_draw=False, user_id=current_user.id).delete(synchronize_session=False)
    db.session.commit()

    flash("All played draws deleted.")
    return lottery()

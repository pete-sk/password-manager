from flask import Blueprint, render_template, request, url_for, flash, redirect, abort
from flask_login import current_user, login_required

from app import db
from app.models import Admin, BlogPost
from app.blog.forms import PostForm

blog = Blueprint('blog', __name__)


@blog.route('/blog')
def blog_home():
    title = 'News & Announcements'
    admin = False
    if current_user.is_authenticated:
        if Admin.query.filter_by(email=current_user.email).first():
            print(Admin.query.filter_by(email=current_user.email).first())
            admin = True
    page = request.args.get('page', 1, type=int)
    posts = BlogPost.query.order_by(BlogPost.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template('blog/blog.html', title=title, posts=posts, admin=admin, home=True)


@blog.route('/blog/posts_by/<string:author>')
def posts_by(author):
    page = request.args.get('page', 1, type=int)
    title = f'Posts by {author}'
    posts = BlogPost.query.filter_by(author=author)\
        .order_by(BlogPost.date_posted.desc())\
        .paginate(page=page, per_page=5)
    return render_template('blog/blog.html', title=title, author=author, posts=posts)


@blog.route('/blog/post/<int:post_id>')
def view_post(post_id):
    admin = False
    if current_user.is_authenticated:
        if Admin.query.filter_by(email=current_user.email).first():
            print(Admin.query.filter_by(email=current_user.email).first())
            admin = True
    post = BlogPost.query.get_or_404(post_id)
    return render_template('blog/post.html', title=post.title, admin=admin, post=post)


@blog.route('/blog/post/new', methods=['GET', 'POST'])
@login_required
def new_post():
    if not Admin.query.filter_by(email=current_user.email).first():
        abort(403)
    title = 'New Post'
    form = PostForm()
    if form.validate_on_submit():
        post = BlogPost(author=form.author.data, title=form.title.data, content=form.content.data)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created.', 'success')
        return redirect(url_for('blog.view_post', post_id=post.id))
    elif request.method == 'GET':
        if request.args.get('author'):
            form.author.data = request.args.get('author')

    return render_template('blog/edit_post.html', title=title, form=form)


@blog.route('/blog/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    if not Admin.query.filter_by(email=current_user.email).first():
        abort(403)
    title = 'Update Post'
    post = BlogPost.query.get_or_404(post_id)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Post has been updated.', 'success')
        return redirect(url_for('blog.view_post', post_id=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.author.data = post.author
        form.content.data = post.content

    return render_template('blog/edit_post.html', title=title, form=form)


@blog.route('/blog/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    if not Admin.query.filter_by(email=current_user.email).first():
        abort(403)
    post = BlogPost.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash('Post has been deleted.', 'success')

    return redirect(url_for('blog.blog_home'))

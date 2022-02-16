from flask import request
from src.models import Posts, db 
def generate_data():
    page=1 #default
    per_page=2 #default
    if 'page' in request.json:
        page = int(request.json['page'])
    
    if 'per_page' in request.json:
        per_page = request.json['per_page']
    
    allPosts = db.session.query(Posts).paginate(page,per_page)
    response = {}
    data=[]
    for i in allPosts.items:
        temp={}
        temp['name']=i.name
        temp['content']=i.content
        data.append(temp)
    response['data']=data
    meta_data={}
    total_posts = Posts.query.count()
    current_pages_visited = per_page*page
    if total_posts > current_pages_visited:
        meta_data['next_page'] = True
    else:
        meta_data['next_page'] = False
    if current_pages_visited == per_page:
        meta_data['previous_page'] = False
    else:
        meta_data['previous_page'] = True
    response['meta_data']=meta_data
    return response
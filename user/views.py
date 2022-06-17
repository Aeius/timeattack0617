from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import permissions
from django.contrib.auth import login, authenticate, logout
from user.models import User

from django.contrib.auth.hashers import make_password

class UserSignView(APIView):
    def post(self, request):
        email = request.data.get('email', '')
        password = request.data.get('password', '')
        user_type = request.data.get('user_type', '')
        hashed_pwd = make_password(password, salt=None, hasher='default')
        User.objects.create(email=email, user_type=user_type, password=hashed_pwd)
        return Response(f"{email}님 회원가입 성공!!")

class UserLoginView(APIView):
    permissions_classes = [permissions.AllowAny]

    # 요청을 보낼 method의 이름으로 함수명을 지어 오버라이딩 해서 사용해야함
    def get(self, request):
        return

    def post(self, request):
        email = request.data.get('username', '')
        password = request.data.get('password', '')
        hashed_pwd = make_password(password, salt=None, hasher='default')
        user = authenticate(request, username=email, password=hashed_pwd)

        if not user:
            return Response({'error': '아이디와 패스워드를 확인해주세요!'})
        login(request, user)
        return Response({'success': '로그인 성공!'})

    def delete(self, request):
        logout(request)
        return Response({'success': '로그아웃 성공!'})

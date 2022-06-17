from re import T
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager


class UserType(models.Model):
    name = models.CharField(max_length=20, primary_key=True)
    def __str__(self):
        return self.name


# custom user model 사용 시 UserManager 클래스와 create_user, create_superuser 함수가 정의되어 있어야 함
class UserManager(BaseUserManager):
    def create_user(self, email, password=None):
        if not email:
            raise ValueError('Users must have an email')
        user = self.model(
            email=email,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    # python manage.py createsuperuser 사용 시 해당 함수가 사용됨
    def create_superuser(self, email, password=None):
        user = self.create_user(
            email=email,
            password=password
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    email = models.EmailField("이메일", max_length=100, unique=True)
    password = models.CharField("비밀번호", max_length=128)
    join_date = models.DateField("가입일", auto_now_add=True)

    is_active = models.BooleanField(default=True)  # 계정활성화 여부
    is_admin = models.BooleanField(default=True)  # 관리자 계정 여부

    user_type = models.ForeignKey(UserType, on_delete=models.CASCADE, null=True)

    USERNAME_FIELD = 'email'  # 로그인 시 사용할 필드 지정
    REQUIRED_FIELDS = []  # createsuperuser 할 때 추가로 요구할 필드 지정
    objects = UserManager()  # custom user 생성 시 필요

    def __str__(self):
        return self.email

    # 로그인 사용자의 특정 테이블의 crud 권한을 설정, perm table의 crud 권한이 들어간다.
    # admin일 경우 항상 True, 비활성 사용자(is_active=False)의 경우 항상 False
    def has_perm(self, perm, obj=None):
        return True

    # 로그인 사용자의 특정 app에 접근 가능 여부를 설정, app_label에는 app 이름이 들어간다.
    # admin일 경우 항상 True, 비활성 사용자(is_active=False)의 경우 항상 False
    def has_module_perms(self, app_label):
        return True

    # admin 권한 설정
    @property
    def is_staff(self):
        return self.is_admin


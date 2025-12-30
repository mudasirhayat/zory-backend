from datetime import datetime

from rest_framework import status
from rest_framework import generics
from django.http import JsonResponse
from rest_framework.pagination import PageNumberPagination
from rest_framework.views import APIView
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.db import IntegrityError, transaction
from rest_framework.viewsets import ModelViewSet
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.generics import ListAPIView
from rest_framework.filters import SearchFilter
from django.utils.timezone import now
from django_filters.rest_framework import DjangoFilterBackend
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta

from core.exception import exception_handler
from core.utils.s3_helper import upload_image_to_s3
from .config.load_secrets import get_secret
from cryptography.fernet import Fernet
import json
from .config.helpers import send_password_reset_email, send_otp_to_dashboard_user, normalize_email
from .models.merchant_user import User
from .models.dashboard_user import DashboardUser, DashboardUserOTP, UserSubscription
from core.models import (
    Business,
    Invite,
    AllowedEmail,
    Role,
    Request,
    Store,
)
from core.serializers import BusinessSerializer
from .models.payment import Plan
from .payment_serializer import PlanSerializer
from .permissions import IsAuthenticated, IsAuthenticatedDashboardUser
from .token import DashboardRefreshToken
from .serializers import (
    ChangePasswordSerializer,
    InActivateUserSerializer,
    ProfileUpdateSerializer,
    UserSerializer,
    SetNewPasswordSerializer,
    CustomTokenObtainPairSerializer,
    ResetPasswordEmailRequestSerializer,
    BusinessRoleSerializer,
    get_highest_role, GoogleAuthSerializer, DashboardUserSerializer, DashboardProfileUpdateSerializer, InvoiceSerializer
)
from rest_framework_simplejwt.token_blacklist.models import (
    OutstandingToken,
    BlacklistedToken,
)
from rest_framework_simplejwt.tokens import AccessToken
from core.utils.helpers import rename_image, translate_text
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import serializers


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class UserRegistrationView(APIView):
    permission_classes = ()

    def post(self, request):
        email = request.data.get("email", "").strip()
        encrypted_token = request.data.get("token")

        if not encrypted_token:
            return Response(
                {"error": "Token is required", "errorArabic": "Token is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        # Load the encryption key
        encryption_key = get_secret(secret_name="FERNET_SECRET_KEY")
        encryption_key = json.loads(encryption_key).get("FERNET_SECRET_KEY")

        if not encryption_key:
            return Response(
                {"error": "Encryption key is missing or invalid",
                 "errorArabic": "Encryption key is missing or invalid"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        fernet = Fernet(encryption_key.encode("utf-8"))
        decrypted_text = fernet.decrypt(encrypted_token.encode()).decode()
        decrypted_data = json.loads(decrypted_text)
        invite_code = decrypted_data
        password = request.data.get("password")
        confirm_password = request.data.get("confirm_password")
        phone = request.data.get("phone")
        vendor_name_arabic = request.data.get("vendor_name_arabic", "").strip()
        vendor_name_english = request.data.get("vendor_name_english", "").strip()
        business_name_arabic = request.data.get("business_name_arabic", "").strip()
        business_name_english = request.data.get("business_name_english", "").strip()

        # Validate uniqueness
        if User.objects.filter(email=email).exists():
            return Response(
                {"error": "User with this email already exists",
                 "errorArabic": "المستخدم بهذا البريد الإلكتروني موجود مُسبقًا."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate email
        if not AllowedEmail.objects.filter(email=email).exists():
            return Response(
                {"error": "This email is not allowed for Signup",
                 "errorArabic": "هذا البريد الإلكتروني غير مسموح له للتسجيل."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate invite
        if not invite_code:
            return Response(
                {"error": "Invite code is required for registration",
                 "errorArabic": "Invite code is required for registration"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate invite existence and association with email
        invite = get_object_or_404(
            Invite, invite_code=invite_code, invited_to=email, is_active=True
        )

        # Validate uniqueness for business name
        if (
                invite.role_type.upper() == "OWNER"
                and business_name_english
                and Business.objects.filter(name_english=business_name_english).exists()
        ):
            raise serializers.ValidationError(
                {"message": "Business with this name already exists",
                 "messageArabic": "Business with this name already exists"},
            )

        # Validate password
        if password != confirm_password:
            return Response(
                {"error": "Password and confirm password do not match",
                 "errorArabic": "Password and confirm password do not match"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate role type
        if invite.role_type not in dict(Role.ROLE).keys():
            return Response(
                {"error": "Invalid role type in the invite", "errorArabic": "Invalid role type in the invite"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if invite.role_type.upper() == "OWNER":
            request_instance = Request.objects.filter(
                request_type="Register Tennant",
                initiator=email,
                request_status=0,
            ).first()
            request_instance.request_status = 2
            request_instance.save()

        if business_name_english or business_name_arabic:
            business_name_english = business_name_english if business_name_english else business_name_arabic
            business_name_arabic = business_name_arabic if business_name_arabic else business_name_english

        if vendor_name_english or vendor_name_arabic:
            vendor_name_english = vendor_name_english if vendor_name_english else vendor_name_arabic
            vendor_name_arabic = vendor_name_arabic if vendor_name_arabic else vendor_name_english

        # Handle Role creation atomically
        with transaction.atomic():
            # Create user
            serializer = UserSerializer(
                data={
                    "name_arabic": vendor_name_arabic,
                    "name_english": vendor_name_english,
                    "email": email,
                    "password": password,
                    "confirm_password": confirm_password,
                    "phone": phone,
                }
            )
            serializer.is_valid(raise_exception=True)
            user = serializer.save()

            # Check if the user already has a role
            if Role.objects.filter(member=user).exists():
                return Response(
                    {
                        "error": "User already have a role and cannot have more than 1 roles.",
                        "errorArabic": "للمستخدم دور مُسبق، ولا يُمكنه الحصول على أكثر من دور واحد."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            token = RefreshToken.for_user(user)
            token["email"] = user.email
            token["user_id"] = user.id
            token["highest_role"] = get_highest_role(user)
            token["english_name"] = user.name_english
            token["arabic_name"] = user.name_arabic
            token["is_super_user"] = user.is_superuser
            token_data = {
                "refresh": str(token),
                "access": str(token.access_token),
            }

            # Business handling
            business = invite.business
            if invite.role_type.upper() == "OWNER":
                business_serializer = BusinessSerializer(
                    data={
                        "name_arabic": business_name_arabic,
                        "name_english": business_name_english,
                        "owner": user.id,
                    }
                )

                business_serializer.is_valid(raise_exception=True)
                business = business_serializer.save()

            Role.objects.create(
                member=user,
                role=invite.role_type,
                business=business,
            )

            # Optionally deactivate the invite after use
            invite.is_active = False
            invite.save()

        # Return success response
        return Response(
            {
                "user": UserSerializer(user).data,
                "message": "User registered successfully.", "messageArabic": "تم تسجيل المستخدم بنجاح.",
                "token": token_data["access"],
            },
            status=status.HTTP_201_CREATED,
        )


class UserView(APIView):
    permission_classes = (IsAuthenticated,)
    parser_classes = (MultiPartParser, FormParser)

    def get(self, request):
        """
        Retrieve user information with their single business and role.
        Since each user can only be associated with one business.
        """
        user = get_object_or_404(User, pk=request.user.id)

        # Get user basic info
        user_data = UserSerializer(user).data
        if user.is_superuser:
            store = Store.objects.all()
            store_request_exists = Request.objects.filter(
                request_type="Add Store",
            ).exists()
            user_data["store_data"] = True if (store or store_request_exists) else False
        else:
            # Get the user's role for their single business
            try:
                role = Role.objects.select_related("business").get(member=user)
                # Add business and role info to the response
                user_data["business_id"] = role.business.id
                user_data["role"] = role.role
                # Check if a store exists for this business
                store = Store.objects.filter(business=role.business_id).first()
                store_request_exists = Request.objects.filter(
                    store_business_id=role.business_id,
                    request_type="Add Store",
                ).exists()
                user_data["store_data"] = (
                    True if (store or store_request_exists) else False
                )
            except Role.DoesNotExist:
                # If user has no business association yet
                user_data["business_id"] = None
                user_data["role"] = None
            except Role.MultipleObjectsReturned:
                # In case there are multiple roles (this shouldn't happen, but as a safeguard)
                # Get the first one
                role = (
                    Role.objects.select_related("business").filter(member=user).first()
                )
                user_data["business_id"] = role.business.id if role else None
                user_data["role"] = role.role if role else None
                user_data["store_data"] = True

        return Response(user_data, status=status.HTTP_200_OK)

    def patch(self, request):
        user = get_object_or_404(User, pk=request.user.id)
        data = request.data

        if (
                request.data.get("profile_picture") in [None, "", "null", "None"]
                and request.data.get("profile_picture_url") in [None, "", "null", "None"]
        ):
            user.profile_picture = None
            user.profile_picture_url = None
            user.save()
        elif "profile_picture" in request.FILES:
            try:
                profile_pic = request.FILES["profile_picture"]

                content_type = profile_pic.content_type

                unique_name = rename_image(user.name_english, profile_pic)

                # Get binary data directly
                profile_pic.seek(0)
                binary_data = profile_pic.read()

                # Upload binary data to S3
                profile_pic_url = upload_image_to_s3(
                    binary_data, unique_name, "user_profile", content_type
                )
                # Add URL to request data
                request.data["profile_picture_url"] = profile_pic_url

            except Exception as e:
                return Response(
                    {"error": f"Failed to upload image: {str(e)}", "errorArabic": f"{str(e)} فشل"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        serializer = ProfileUpdateSerializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request):
        user = get_object_or_404(User, pk=request.user.id)
        serializer = InActivateUserSerializer(user, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"msg": "User has been scheduled for deletion successfully.", "msgArabic": "تم بنجاح"},
            status=status.HTTP_200_OK,
        )


class DeleteUser(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        user_to_delete = get_object_or_404(User, pk=pk)
        requesting_user = request.user

        # Check if the requesting user is an Owner or Admin
        if not Role.objects.filter(member=requesting_user, role__in=["OWNER"]).exists():
            return Response(
                {"detail": "Only Owners can delete users.",
                 "detailArabic": "المالكون فقط هم من يستطيعون حذف المستخدمين."},
                status=status.HTTP_403_FORBIDDEN,
            )

        user_to_delete.delete()
        return Response(
            {"msg": "User has been deleted successfully.", "msgArabic": "تم بنجاح."}, status=status.HTTP_200_OK
        )


class ChangePasswordView(APIView):
    permission_classes = (IsAuthenticated,)

    def patch(self, request):
        user = get_object_or_404(User, pk=request.user.id)
        serializer = ChangePasswordSerializer(user, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"msg": "Password updated successfully.", "msgArabic": "Password updated successfully."},
            status=status.HTTP_200_OK
        )


class ChangePasswordDashboardView(APIView):
    permission_classes = (IsAuthenticatedDashboardUser,)

    def patch(self, request):
        user = get_object_or_404(DashboardUser, pk=request.user.id)

        if user.google_auth_enabled:
            return Response(
                {"error": "google users cannot change password"}, status=status.HTTP_400_BAD_REQUEST
            )

        serializer = ChangePasswordSerializer(user, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"msg": "Password updated successfully."}, status=status.HTTP_200_OK
        )


class SetNewPasswordAPIView(generics.GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        user_type: str = request.data.get('user_type')

        user_model = User
        if user_type == 'dashboard':
            user_model = DashboardUser

        serializer = self.serializer_class(
            data=request.data,
            context={'user_model': user_model}
        )
        serializer.is_valid(raise_exception=True)
        return Response(
            {"success": True, "message": "Password reset success",
             "messageArabic": "تم إعادة تعيين كلمة المرور بنجاح."},
            status=status.HTTP_200_OK,
        )


class ForgotPasswordAPIView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        user_type: str = request.data.get('user_type')

        user_model = User
        if user_type == 'dashboard':
            user_model = DashboardUser

        serializer = ResetPasswordEmailRequestSerializer(
            data=request.data,
            context={'user_model': user_model}
        )
        serializer.is_valid(raise_exception=True)

        user = get_object_or_404(user_model, email=serializer.validated_data["email"])
        send_password_reset_email(user)

        return Response(
            {"msg": f"Success",
             "msgArabic": f"تم بنجاح"},
            status=status.HTTP_200_OK,
        )


class UserListView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can access

    def get(self, request):
        user = request.user

        # Get query parameters for filtering
        name_filter = request.query_params.get("name", None)
        role_filter = request.query_params.get("role", None)
        status_filter = request.query_params.get("status", None)
        business = request.query_params.get("business_id", None)

        data = []

        if user.is_superuser:
            # Superuser can view all users with roles in a specific business
            roles_qs = Role.objects.select_related("member", "business").all()

            if business:
                roles_qs = roles_qs.filter(business=business)

            if role_filter:
                roles_qs = roles_qs.filter(role=role_filter)

            if name_filter:
                roles_qs = roles_qs.filter(member__name_english__icontains=name_filter)

            if status_filter:
                is_active = status_filter.lower() == "active"
                roles_qs = roles_qs.filter(member__is_active=is_active)

            for role in roles_qs:
                data.append(
                    {
                        "id": role.member.id,
                        "name_english": role.member.name_english,
                        "role": role.role if role.role else "Unknown",
                        "email_address": role.member.email,
                        "status": role.member.is_active,
                    }
                )
        else:

            # Get the user's roles
            user_roles = Role.objects.filter(member=user)

            user_ids = set()

            # Determine which users they can see based on their role
            if user_roles.filter(role="OWNER").exists():
                # Owners can see all Admins and Viewers they have added
                owner_visible_users = Role.objects.filter(
                    business__in=user_roles.values_list("business", flat=True)
                ).exclude(member=user)

                # Apply role filtering if specified
                if role_filter:
                    owner_visible_users = owner_visible_users.filter(role=role_filter)

                user_ids.update(owner_visible_users.values_list("member", flat=True))

            elif user_roles.filter(role="ADMIN").exists():
                # Admins can only see Viewers they have added
                admin_visible_users = Role.objects.filter(
                    role="VIEWER" if not role_filter else role_filter,
                    business__in=user_roles.values_list("business", flat=True),
                ).exclude(member=user)

                user_ids.update(admin_visible_users.values_list("member", flat=True))

            # Fetch user details
            users = User.objects.filter(id__in=user_ids)

            # Apply name filter if specified
            if name_filter:
                users = users.filter(name_english__icontains=name_filter)

            # Apply status filter if specified
            if status_filter:
                is_active = status_filter.lower() == "active"
                users = users.filter(is_active=is_active)

            for user_obj in users:
                user_role = Role.objects.filter(member=user_obj).first()

                # Skip if role filtering is applied and this user's role doesn't match
                if role_filter and user_role and user_role.role != role_filter:
                    continue

                data.append(
                    {
                        "id": user_obj.id,
                        "name_english": user_obj.name_english,
                        "role": user_role.role if user_role else "Unknown",
                        "email_address": user_obj.email,
                        "status": user_obj.is_active,
                    }
                )

        return Response(data, status=status.HTTP_200_OK)


class UpdateUserRole(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        user_to_update = get_object_or_404(User, pk=pk)
        requesting_user = request.user

        # Check if the requesting user is an Owner
        if not Role.objects.filter(member=requesting_user, role="OWNER").exists():
            return Response(
                {"detail": "Only owners can change user roles.", "detailArabic": "Only owners can change user roles."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Get the new role from the request
        new_role = request.data.get("role")
        if new_role not in ["ADMIN", "VIEWER"]:
            return Response(
                {"detail": "Invalid role provided.", "detailArabic": "Invalid role provided."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Ensure only Admin to Viewer changes are allowed
        existing_role = Role.objects.filter(member=user_to_update).first()
        if existing_role and existing_role.role == "ADMIN" and new_role == "VIEWER":
            existing_role.role = new_role
            existing_role.save()
            return Response(
                {"msg": "User role updated successfully.", "msgArabic": "تم بنجاح."}, status=status.HTTP_200_OK
            )

        return Response(
            {"detail": "Only Admins can be changed to Viewers.",
             "detailArabic": "يمكن تغيير المشرفين فقط إلى مُشاهدين."},
            status=status.HTTP_400_BAD_REQUEST,
        )


class UpdateUserStatus(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        user_to_update = get_object_or_404(User, pk=pk)
        requesting_user = request.user

        # Check if the requesting user is an Owner or Admin
        if not Role.objects.filter(member=requesting_user, role__in=["OWNER"]).exists():
            return Response(
                {"detail": "Only Owners can change user status.",
                 "detailArabic": "Only Owners can change user status."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Get the new status from request
        is_active = request.data.get("is_active")

        # Convert string values to proper boolean
        if isinstance(is_active, str):
            is_active = is_active.lower() == "true"

        # Validate that is_active is a boolean
        if not isinstance(is_active, bool):
            return Response(
                {"detail": "'is_active' should be a boolean value (true/false).",
                 "detailArabic": "'is_active' should be a boolean value (true/false)."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Update the user's status
        user_to_update.is_active = is_active
        user_to_update.save()
        return Response(
            {"msg": f"User status updated to {'Active' if is_active else 'Inactive'}.",
             "msgArabic": f"User status updated to {'Active' if is_active else 'Inactive'}."},
            status=status.HTTP_200_OK,
        )


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Get the token from the Authorization header
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
return Response({
    "error": "Invalid authorization header format",
    "errorArabic": "Invalid authorization header format"
})
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Extract the access token
            token_string = auth_header.split(" ")[1]

            # Process the token
            token = AccessToken(token_string)
            jti = token.payload["jti"]
            user_id = token.payload["user_id"]

            expires_at = datetime.fromtimestamp(token.payload.get("exp"))

            # First, create or get the OutstandingToken
            outstanding_token = OutstandingToken.objects.create(
                user_id=user_id,
                jti=jti,
                token=token_string,
                expires_at=expires_at,
                created_at=now(),
            )

            # Then explicitly create the BlacklistedToken
            blacklisted_token = BlacklistedToken.objects.create(
                token=outstanding_token, blacklisted_at=now()
            )

            return Response(
                {
                    "message": "Logout successful", "messageArabic": "تم بنجاح",
                    "token_blacklisted": True,
                    "outstanding_token_id": outstanding_token.id,
                    "blacklisted_token_id": blacklisted_token.id,
                },
                status=status.HTTP_200_OK,
            )

        except IntegrityError as ie:
            # Handle duplicate key errors (token already blacklisted)
            return Response(
                {"message": "Logout successful", "messageArabic": "تم بنجاح", "already_blacklisted": True},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(
                {"error": f"Logout failed: {str(e)}", "errorArabic": f"{str(e)} فشل "},
                status=status.HTTP_400_BAD_REQUEST,
            )


class BusinessRoleListView(ListAPIView):
    serializer_class = BusinessRoleSerializer
    permission_classes = [IsAdminUser]
    queryset = Role.objects.select_related("member", "business")
    filter_backends = [DjangoFilterBackend, SearchFilter]
    filterset_fields = {
        "member__is_active": ["exact"],
        "role": ["exact"],
    }
    search_fields = ["business__name_english", "business__name_arabic"]


class GoogleAuthAPIView(APIView):
    """ Google OAuth authentication endpoint """
    permission_classes = [AllowAny]

    @exception_handler()
    def post(self, request):
        serializer = GoogleAuthSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()
            token = DashboardRefreshToken.for_user(user)
            token["email"] = user.email
            token["user_id"] = user.id
            token["english_name"] = user.name_english
            token["arabic_name"] = user.name_arabic

            free_plan = get_object_or_404(Plan, name="Free Trial")
            UserSubscription.objects.create(
                user=user,
                plan=free_plan,
                current_credits=free_plan.credits,
                is_active=True,
                auto_renew=False,
                status='Completed'
            )
            return {'access': str(token.access_token),
                    'refresh': str(token),
                    "profile_pic": user.profile_picture_url,
                    "plan_name": user.active_subscription.plan.name if user.active_subscription else None,
                    "current_credits": user.active_subscription.current_credits if user.active_subscription else None,
                    "features_info": user.get_feature_info()
                    }

        raise serializers.ValidationError(serializer.errors)


class DashboardUserRegistrationView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        email = request.data.get("email", "").strip()
        password = request.data.get("password")
        confirm_password = request.data.get("confirm_password")
        name_arabic = request.data.get("name_arabic", "").strip()
        name_english = request.data.get("name_english", "").strip()

        email = normalize_email(email)

        # Validate password
        if password != confirm_password:
            return Response(
                {"error": "Password and confirm password do not match"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Translate name if provided
        if name_english or name_arabic:
            input_name = name_arabic if name_arabic else name_english
            # translated = translate_text(input_name)
            name_english = input_name
            name_arabic = input_name

        # Check if user exists
        existing_user = DashboardUser.objects.filter(email=email).first()

        if existing_user:
            if existing_user.google_auth_enabled:
                return Response(
                    {"error": "User already registered using Google."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if existing_user.is_active:
                return Response(
                    {"error": "User with this email already exists."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            existing_user.set_password(password)
            existing_user.name_english = name_english
            existing_user.name_arabic = name_arabic
            existing_user.save(update_fields=["password", "name_english", "name_arabic"])

            send_otp_to_dashboard_user(existing_user)

            return Response(
                {"message": "OTP resent to your email. Please verify to complete registration."},
                status=status.HTTP_200_OK
            )

        dashboard_user_serializer = DashboardUserSerializer(
            data={
                "name_arabic": name_arabic,
                "name_english": name_english,
                "email": email,
                "password": password,
                "confirm_password": confirm_password,
            }
        )
        dashboard_user_serializer.is_valid(raise_exception=True)
        new_user = dashboard_user_serializer.save()
        new_user.is_active = False
        new_user.save(update_fields=["is_active"])

        send_otp_to_dashboard_user(new_user)

        return Response(
            {"message": "OTP sent to your email. Please verify to complete registration."},
            status=status.HTTP_201_CREATED,
        )


class VerifyDashboardUserOtpAndActivateView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        otp = request.data.get("otp")
        if not email or not otp:
            return Response({"error": "Email and OTP are required."}, status=status.HTTP_400_BAD_REQUEST
            return Response({"error": "Email and OTP are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = DashboardUser.objects.get(email=email)
            otp_obj = user.otp
        except (DashboardUser.DoesNotExist, DashboardUserOTP.DoesNotExist):
            return Response({"error": "Invalid user or OTP."}, status=status.HTTP_400_BAD_REQUEST)

        if not otp_obj.is_valid(otp):
            return Response({"error": "Invalid or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)

        # Mark verified
        user.is_active = True
        user.save(update_fields=["is_active"])

        otp_obj.mark_verified()
        otp_obj.expire()

        refresh = DashboardRefreshToken.for_user(user)
        refresh["email"] = user.email
        refresh["user_id"] = user.id
        refresh["english_name"] = user.name_english
        refresh["arabic_name"] = user.name_arabic

        token_data = {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }

        free_plan = get_object_or_404(Plan, name="Free Trial")
        UserSubscription.objects.create(
            user=user,
            plan=free_plan,
            current_credits=free_plan.credits,
            is_active=True,
            auto_renew=False,
            status='Completed'
        )
        return Response(
            {
                "message": "User registered successfully.",
                "token": token_data["access"],
                "refresh": token_data["refresh"],
                "profile_pic": user.profile_picture_url,
                "plan_name": user.active_subscription.plan.name if user.active_subscription else None,
                "current_credits": user.active_subscription.current_credits if user.active_subscription else None,
                "features_info": user.get_feature_info(),
            },
            status=status.HTTP_201_CREATED,
        )


class DashboardUserSignInView(APIView):
    """
  Dashboard user sign-in endpoint.
  Matches your registration response format.
  """
    permission_classes = (AllowAny,)

    @exception_handler()
    def post(self, request):
        email = request.data.get("email", "").strip()
        password = request.data.get("password", "").strip()

        # Validate required fields
        if not email:
            raise ValidationError("Email is required")

        if not password:
            raise ValidationError("Password is required")

        user = get_object_or_404(DashboardUser, email=email)

        # Verify password
        if not user.check_password(password):
            raise ValidationError("Invalid password. Please Enter correct password")

        if not hasattr(user, 'otp') or not user.otp.is_verified:
            raise ValidationError("Please complete your registration using the OTP sent.")

        if not user.is_active:
            raise ValidationError("Email not verified.")

        # Create token (same format as your registration)
        token = DashboardRefreshToken.for_user(user)
        token["email"] = user.email
        token["user_id"] = user.id
        token["english_name"] = user.name_english
        token["arabic_name"] = user.name_arabic

        token_data = {
            "refresh": str(token),
            "access": str(token.access_token),
        }
        # Return success response (matches registration format)
        return {
            "access": token_data["access"],
            "refresh": token_data["refresh"],
            "profile_pic": user.profile_picture_url,
            "plan_name": user.active_subscription.plan.name if user.active_subscription else None,
            "current_credits": user.active_subscription.current_credits if user.active_subscription else None,
            "features_info": user.get_feature_info()
        }


class DashboardUserView(APIView):
    permission_classes = (IsAuthenticatedDashboardUser,)

    @exception_handler()
    def get(self, request):
        user = get_object_or_404(DashboardUser, pk=request.user.id)

        user_data = DashboardUserSerializer(user).data
        if user.active_subscription:
            subscription = user.active_subscription
            plan_data = PlanSerializer(subscription.plan).data

try:
    subscription_end = subscription.subscription_end
    next_recurring_date = subscription_end + timedelta(days=1) if subscription_end else None
    days_left = (subscription_end - timezone.now()).days if subscription_end else None
except AttributeError
            if days_left is not None and days_left < 0:
                days_left = 0

            next_recurring_date_str = (
                next_recurring_date.strftime("%b %d, %Y") if next_recurring_date else None
            )

            user_data['current_plan'] = {
                **plan_data,
                "next_billing_date": next_recurring_date_str,
                "days_left": days_left
            }
            text_to_image = round((subscription.get_usage_credits("text_to_image") / plan_data["credits"]) * 100)
            sketch_to_render = round((subscription.get_usage_credits("sketch_to_render") / plan_data["credits"]) * 100)
            object_removal = round((subscription.get_usage_credits("object_removal") / plan_data["credits"]) * 100)
            home_redesign = round((subscription.get_usage_credits("home_redesign") / plan_data["credits"]) * 100)

            user_data['credit_usage'] = {
                "text_to_image": f"{text_to_image}%",
                "sketch_to_render": f"{sketch_to_render}%",
                "object_removal": f"{object_removal}%",
                "home_redesign": f"{home_redesign}%"
            }
            user_data['credit_consumed'] = {
                "total_credits": f"{subscription.get_usage_credits('current_credits')}/{plan_data['credits']}",
                "text_to_image": f"{subscription.get_usage_credits('text_to_image')}/{plan_data['credits']}",
                "sketch_to_render": f"{subscription.get_usage_credits('sketch_to_render')}/{plan_data['credits']}",
                "object_removal": f"{subscription.get_usage_credits('object_removal')}/{plan_data['credits']}",
                "home_redesign": f"{subscription.get_usage_credits('home_redesign')}/{plan_data['credits']}"
            }
        else:
            user_data['current_plan'] = None
            user_data['credit_usage'] = None
            user_data['credit_consumed'] = None

        return Response(user_data)

    def patch(self, request):
        user = get_object_or_404(DashboardUser, pk=request.user.id)

        if (
                request.data.get("profile_picture") in [None, "", "null", "None"]
                and request.data.get("profile_picture_url") in [None, "", "null", "None"]
        ):
            user.profile_picture = None
            user.profile_picture_url = None
            user.save()
        elif "profile_picture" in request.FILES:
            try:
                profile_pic = request.FILES["profile_picture"]

                content_type = profile_pic.content_type

                unique_name = rename_image(user.name_english, profile_pic)

                # Get binary data directly
                profile_pic.seek(0)
                binary_data = profile_pic.read()

                # Upload binary data to S3
                profile_pic_url = upload_image_to_s3(
                    binary_data, unique_name, "dashboard_user_profile", content_type
                )
                # Add URL to request data
                request.data["profile_picture_url"] = profile_pic_url

            except Exception as e:
                return Response(
                    {"error": f"Failed to upload image: {str(e)}", "errorArabic": f"{str(e)} فشل"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        serializer = DashboardProfileUpdateSerializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    @exception_handler()
    def delete(self, request):
        user = get_object_or_404(DashboardUser, pk=request.user.id)
        user.delete()
        return Response(
            {"msg": "User  delete successfully.", "msgArabic": "تم بنجاح"},
            status=status.HTTP_200_OK,
        )


class DashboardLogoutView(APIView):
    permission_classes = [IsAuthenticatedDashboardUser]

    def post(self, request):
        try:
            # Get the token from the Authorization header
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return Response(
                    {"error": "Invalid authorization header format",
                     "errorArabic": "Invalid authorization header format"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Extract the access token
            token_string = auth_header.split(" ")[1]

            # Process the token
            token = AccessToken(token_string)
            jti = token.payload["jti"]
            user_id = token.payload["user_id"]

            expires_at = datetime.fromtimestamp(token.payload.get("exp"))

            outstanding_token = OutstandingToken.objects.create(
                user=None,  # :white_check_mark: Set to None for dashboard users
                jti=jti,
                token=token_string,
                expires_at=expires_at,
                created_at=now(),
            )

            # Then explicitly create the BlacklistedToken
            blacklisted_token = BlacklistedToken.objects.create(
                token=outstanding_token, blacklisted_at=now()
            )

            return Response(
                {
                    "message": "Logout successful", "messageArabic": "تم بنجاح",
                    "token_blacklisted": True,
                    "outstanding_token_id": outstanding_token.id,
                    "blacklisted_token_id": blacklisted_token.id,
                },
                status=status.HTTP_200_OK,
            )

        except IntegrityError as ie:
            # Handle duplicate key errors (token already blacklisted)
            return Response(
                {"message": "Logout successful", "messageArabic": "تم بنجاح", "already_blacklisted": True},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(
                {"error": f"Logout failed: {str(e)}", "errorArabic": f"{str(e)} فشل "},
                status=status.HTTP_400_BAD_REQUEST,
            )


class PlanViewSet(ModelViewSet):
    serializer_class = PlanSerializer
    queryset = Plan.objects.all()

    def get_permissions(self):
        if self.request.method in ['GET', 'HEAD', 'OPTIONS']:
            return [IsAuthenticatedDashboardUser()]
        return [IsAdminUser()]

    @exception_handler()
    def list(self, request, *args, **kwargs):
        user = request.user
        plans = self.queryset

excluded_plans = []

if user.has_one_time_subscription(plan__name="Free trial", is_active=False):
            excluded_plans.append("Free Trial")
        if user.has_one_time_subscription(plan__name="Starter", is_active=False):
            excluded_plans.append("Starter")

        if excluded_plans:
            plans = plans.exclude(name__in=excluded_plans)

        duration_priority = {
            "one time plan": 0,
            "monthly": 1,
            "yearly": 2
        }

        plans = sorted(
            plans,
            key=lambda p: (duration_priority.get(p.duration_type.lower(), 99), p.id)
        )

        response_data = []
        for plan in plans:
            serialized = PlanSerializer(plan).data
            active_sub = user.active_subscription
try:
    serialized['active'] = (
        active_sub is not None and active_sub.plan_id == plan.id
    )
except Exception as e:
    print(f"Error: {e}")
else:
    response_data.append(serial

        return response_data


class StandardResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = "page_size"
    max_page_size = 100


class InvoiceViewSet(APIView):
    serializer_class = InvoiceSerializer
    pagination_class = StandardResultsSetPagination

    @exception_handler()
    def get(self, request):
        qs = (
            UserSubscription.objects
            .filter(user_id=request.user.id)
            .order_by("-subscription_start")
        )

        paginator = self.pagination_class()
        page = paginator.paginate_queryset(qs, request)
        if page is not None:
            serializer = self.serializer_class(page, many=True)
            return paginator.get_paginated_response(serializer.data)

        serializer = self.serializer_class(qs, many=True)
        return serializer.data

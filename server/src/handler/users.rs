use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Multipart, Query},
    middleware,
    response::IntoResponse,
    routing::{get, post, put},
};
use tower_http::limit::RequestBodyLimitLayer;
use validator::Validate;

use crate::{
    config::AppState,
    db::UserExt,
    dtos::{
        FilterUserDto, GroupUpdateDto, RequestQueryDto, Response, UserData, UserListResponseDto,
        UserPasswordUpdateDto, UserResponseDto, UsernameUpdateDto, VerifyUserDto,
    },
    error::{ErrorMessage, HttpError},
    middleware::{JWTAuthMiddeware, group_check},
    models::UserGroup,
    utils::file::{create_file, write_file},
};

// TODO: macro?

pub fn user_handler() -> Router {
    // TODO: cmp iat with updated

    let upload = Router::new()
        .route("/", post(upload_file))
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(
            2048 * 1024 * 1024, // 2GB
        ));

    Router::new()
        .route(
            "/me",
            get(get_me).layer(middleware::from_fn(|state, req, next| {
                group_check(state, req, next, vec![UserGroup::Admin, UserGroup::User])
            })),
        )
        .route(
            "/users",
            get(get_users).layer(middleware::from_fn(|state, req, next| {
                group_check(state, req, next, vec![UserGroup::Admin])
            })),
        )
        .route("/name", put(update_user_name))
        .route("/group", put(update_user_group))
        .route("/password", put(update_user_password))
        .nest("/upload", upload)
}

pub async fn get_me(
    Extension(_app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddeware>,
) -> Result<impl IntoResponse, HttpError> {
    let filtered_user = FilterUserDto::filter_user(&user.user);

    let response_data = UserResponseDto {
        status: "success".to_string(),
        data: UserData {
            user: filtered_user,
        },
    };

    Ok(Json(response_data))
}

pub async fn get_users(
    Query(query_params): Query<RequestQueryDto>,
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, HttpError> {
    query_params
        .validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let page = query_params.page.unwrap_or(1);
    let limit = query_params.limit.unwrap_or(10);

    let users = app_state
        .db_client
        .get_users(page as u32, limit)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user_count = app_state
        .db_client
        .get_user_count()
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = UserListResponseDto {
        status: "success".to_string(),
        users: FilterUserDto::filter_users(&users),
        results: user_count,
    };

    Ok(Json(response))
}

pub async fn verify_user(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddeware>,
    Json(body): Json<VerifyUserDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    // TODO: group_check

    let user = &user.user;
    if user.group != UserGroup::Admin {
        return Err(HttpError::unauthorized(
            ErrorMessage::PermissionDenied.to_string(),
        ));
    }

    create_file(
        Extension(app_state.clone()),
        body.username.clone(),
        Some(body.username.clone()),
    )
    .await
    .map_err(|e| HttpError::server_error(e.to_string()))?;

    let result = app_state
        .db_client
        .verify_user(body.username)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let filtered_user = FilterUserDto::filter_user(&result);

    let response = UserResponseDto {
        data: UserData {
            user: filtered_user,
        },
        status: "success".to_string(),
    };

    Ok(Json(response))
}

pub async fn update_user_name(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddeware>,
    Json(body): Json<UsernameUpdateDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = &user.user;

    let user_id = uuid::Uuid::parse_str(&user.id.to_string()).unwrap();

    let result = app_state
        .db_client
        .update_username(user_id, &body.username)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let filtered_user = FilterUserDto::filter_user(&result);

    let response = UserResponseDto {
        data: UserData {
            user: filtered_user,
        },
        status: "success".to_string(),
    };

    Ok(Json(response))
}

pub async fn update_user_group(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddeware>,
    Json(body): Json<GroupUpdateDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = &user.user;

    let user_id = uuid::Uuid::parse_str(&user.id.to_string()).unwrap();

    let result = app_state
        .db_client
        .update_user_group(user_id, body.group)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let filtered_user = FilterUserDto::filter_user(&result);

    let response = UserResponseDto {
        data: UserData {
            user: filtered_user,
        },
        status: "success".to_string(),
    };

    Ok(Json(response))
}

pub async fn update_user_password(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddeware>,
    Json(body): Json<UserPasswordUpdateDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = &user.user;

    let user_id = uuid::Uuid::parse_str(&user.id.to_string()).unwrap();

    let result = app_state
        .db_client
        .get_user(Some(user_id), None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result.ok_or(HttpError::unauthorized(
        ErrorMessage::InvalidToken.to_string(),
    ))?;

    if user.password != body.old_password {
        return Err(HttpError::bad_request(
            "Old password is incorrect".to_string(),
        ));
    }

    app_state
        .db_client
        .update_user_password(user_id, body.new_password)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = Response {
        message: "Password updated Successfully".to_string(),
        status: "success",
    };

    Ok(Json(response))
}

pub async fn upload_file(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddeware>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, HttpError> {
    while let Some(field) = multipart.next_field().await.unwrap() {
        // TODO: make use of chunk()

        // TODO: clean

        // while let Some(field_chunk) = field.chunk().await.unwrap() {
        //     println!("{}", field_chunk.len());
        // }
        // let name = field.name().unwrap().to_string();
        // let file_name = field.file_name().unwrap().to_string();
        // let content_type = field.content_type().unwrap().to_string();
        let data = field.bytes().await.unwrap();

        let upload_filename = create_file(Extension(app_state.clone()), &user.user.username, None)
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;

        write_file(
            Extension(app_state.clone()),
            &user.user.username,
            &upload_filename,
            &data,
        )
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

        eprintln!("length of file is {} bytes", data.len());
    }
    // TODO: return filename
    // deal with storage limit
    Ok(Json(""))
}

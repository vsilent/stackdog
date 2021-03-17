table! {
    users (id) {
        id -> Integer,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        username -> Text,
        email -> Text,
        password -> Text,
        login_session -> Text,
    }
}

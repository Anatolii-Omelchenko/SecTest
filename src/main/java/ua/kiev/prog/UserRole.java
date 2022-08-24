package ua.kiev.prog;

public enum UserRole {
    ADMIN, USER, MODERATOR;

    @Override
    public String toString() {
        return "ROLE_" + name();
    }
}

package ru.softdarom.security.oauth2.dto.base;

public enum TokenValidType {

    VALID {
        @Override
        public boolean isValid() {
            return true;
        }
    },
    EXPIRED,
    INCORRECT,
    UNKNOWN;


    public boolean isValid() {
        return false;
    }

}
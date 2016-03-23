CREATE USER 'rodauth_test'@'localhost' IDENTIFIED BY 'rodauth_test';
CREATE USER 'rodauth_test_password'@'localhost' IDENTIFIED BY 'rodauth_test';
CREATE DATABASE rodauth_test;
GRANT ALL ON rodauth_test.* TO 'rodauth_test_password'@'localhost' WITH GRANT OPTION;

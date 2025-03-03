
CREATE DATABASE IF NOT EXISTS feur_auth_system;


USE feur_auth_system;


CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    birthday DATE,
    age INT,
    gender ENUM('male', 'female', 'other'),
    status ENUM('parent', 'student'),
    contact_number VARCHAR(15),
    is_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL
);


CREATE TABLE password_reset_codes (
    reset_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    reset_code VARCHAR(6) NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);


CREATE TABLE user_activity_logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    activity_type ENUM('login', 'logout', 'password_change', 'password_reset', 'signup', 'account_update'),
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);


CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_reset_codes ON password_reset_codes(reset_code);
CREATE INDEX idx_reset_user ON password_reset_codes(user_id);


DELIMITER //
CREATE PROCEDURE generate_reset_code(IN user_email VARCHAR(100))
BEGIN
    DECLARE user_exists INT;
    DECLARE user_id_val INT;
    DECLARE reset_code_val VARCHAR(6);
    
   
    SELECT COUNT(*), user_id INTO user_exists, user_id_val 
    FROM users 
    WHERE email = user_email;
    
    IF user_exists > 0 THEN
       
        SET reset_code_val = LPAD(FLOOR(RAND() * 1000000), 6, '0');
        
      
        INSERT INTO password_reset_codes (user_id, reset_code, expires_at) 
        VALUES (user_id_val, reset_code_val, DATE_ADD(NOW(), INTERVAL 1 HOUR));
        
        
        SELECT reset_code_val AS reset_code;
    ELSE
        
        SELECT NULL AS reset_code;
    END IF;
END //
DELIMITER ;


DELIMITER //
CREATE PROCEDURE verify_reset_code(IN email_val VARCHAR(100), IN code_val VARCHAR(6), OUT is_valid BOOLEAN)
BEGIN
    DECLARE code_count INT;
    
    SELECT COUNT(*) INTO code_count
    FROM password_reset_codes prc
    JOIN users u ON prc.user_id = u.user_id
    WHERE u.email = email_val 
      AND prc.reset_code = code_val 
      AND prc.is_used = FALSE 
      AND prc.expires_at > NOW();
      
    IF code_count > 0 THEN
        SET is_valid = TRUE;
    ELSE
        SET is_valid = FALSE;
    END IF;
END //
DELIMITER ;


DELIMITER //
CREATE PROCEDURE update_password(IN email_val VARCHAR(100), IN new_password_hash VARCHAR(255), IN code_val VARCHAR(6), OUT success BOOLEAN)
BEGIN
    DECLARE user_id_val INT;
    DECLARE valid_code BOOLEAN DEFAULT FALSE;
    
    
    SELECT user_id INTO user_id_val FROM users WHERE email = email_val;
    
    
    CALL verify_reset_code(email_val, code_val, valid_code);
    
    IF valid_code = TRUE THEN
        
        UPDATE users SET password_hash = new_password_hash WHERE user_id = user_id_val;
        
     
        UPDATE password_reset_codes 
        SET is_used = TRUE 
        WHERE user_id = user_id_val AND reset_code = code_val;
        
      
        INSERT INTO user_activity_logs (user_id, activity_type)
        VALUES (user_id_val, 'password_reset');
        
        SET success = TRUE;
    ELSE
        SET success = FALSE;
    END IF;
END //
DELIMITER ;


DELIMITER //
CREATE EVENT clean_expired_reset_codes
ON SCHEDULE EVERY 1 DAY
DO
BEGIN
    DELETE FROM password_reset_codes WHERE expires_at < NOW();
END //
DELIMITER ;
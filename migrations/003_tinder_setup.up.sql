-- Add columns to users
ALTER TABLE users 
  ADD COLUMN bio VARCHAR(40) NOT NULL,
  ADD COLUMN gender ENUM('Male', 'Female', 'Other') NOT NULL,
  ADD COLUMN age INT NOT NULL CHECK (age BETWEEN 16 AND 60),
  ADD COLUMN img_path VARCHAR(100);

-- Matches table
CREATE TABLE matches (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    matched_user_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_match (user_id, matched_user_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (matched_user_id) REFERENCES users(id)
);

-- Swipes table
CREATE TABLE swipes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    swiper_id INT NOT NULL,          
    swiped_id INT NOT NULL,          
    is_like BOOLEAN NOT NULL,        
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (swiper_id) REFERENCES users(id),
    FOREIGN KEY (swiped_id) REFERENCES users(id),
    UNIQUE KEY unique_swipe (swiper_id, swiped_id)
);

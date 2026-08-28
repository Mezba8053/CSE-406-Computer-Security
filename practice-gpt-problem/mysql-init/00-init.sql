CREATE USER IF NOT EXISTS 'appuser'@'%' IDENTIFIED BY 'apppassword';
GRANT ALL PRIVILEGES ON academy_lab.* TO 'appuser'@'%';
GRANT ALL PRIVILEGES ON community_lab.* TO 'appuser'@'%';
FLUSH PRIVILEGES;

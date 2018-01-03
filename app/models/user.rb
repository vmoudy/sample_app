class User < ApplicationRecord
  before_save { self.email = email.downcase }
  validates(:name, presence: true, length: { maximum: 50 })

  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
  validates(:email, presence: true,length: { maximum: 255 }, format: { with: VALID_EMAIL_REGEX }, uniqueness: { case_sensitive: false })


  # Valid password contains 1 digit
  # contains 1 upper and 1 lowercase
  # and is in between 8 and 40 chars long
  # and one of these special characters !@#$%^&*
  VALID_PASSWORD_REGEX = /\A(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,40}\z/
  validates(:password, presence: true, length: { in: 8..40 }, format: { with: VALID_PASSWORD_REGEX})
  has_secure_password
end

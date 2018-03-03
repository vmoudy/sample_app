class User < ApplicationRecord

  attr_accessor :remember_token

  before_save { self.email = email.downcase }
  validates(:name, presence: true, length: { maximum: 50 })

  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
  validates(:email, presence: true,length: { maximum: 255 }, format: { with: VALID_EMAIL_REGEX }, uniqueness: { case_sensitive: false })


  # Valid password contains 1 digit
  # contains 1 upper and 1 lowercase
  # is in between 8 and 40 chars long
  # and one of these special characters !@#$%^&*
  VALID_PASSWORD_REGEX = /\A(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,40}\z/
  validates(:password, presence: true, length: { in: 8..40 }, format: { with: VALID_PASSWORD_REGEX})
  has_secure_password

  # Returns the hash digest of the given string.
  def User.digest(string)
    cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST : BCrypt::Engine.cost

    BCrypt::Password.create(string, cost: cost)
  end

   # Returns a random token.
  def User.new_token
    SecureRandom.urlsafe_base64
  end

  # Remembers a user in the database for use in persistent sessions.
  def remember
    self.remember_token = User.new_token
    update_attribute(:remember_digest, User.digest(remember_token))
  end


  # Returns true if the given token matches the digest.
  def authenticated?(remember_token)
    return false if remember_digest.nil?
    BCrypt::Password.new(remember_digest).is_password?(remember_token)
  end

  # Forget a user
  def forget
    update_attribute(:remember_digest, nil)
  end
end

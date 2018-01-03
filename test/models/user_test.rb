require 'test_helper'

class UserTest < ActiveSupport::TestCase

  def setup
    @user = User.new(name: "Example User", email: "user@example.com", password: "fo@B ar12", password_confirmation: "fo@B ar12")
  end

  test "should be valid" do
    assert @user.valid?
  end

  test "name should be present" do
    @user.name = "a" * 51
    assert_not @user.valid?
  end

  test "email should be present" do
    @user.email = "a" * 244 + "@example.com"
    assert_not @user.valid?
  end

  test "email validation should accept valid addresses" do
    valid_addresses = %w[user@example.com USER@foo.COM A_US-ER@foo.bar.org
                         first.last@foo.jp alice+bob@baz.cn]

    valid_addresses.each do | valid_address |
      @user.email = valid_address
      assert @user.valid?, "#{valid_address.inspect} should be valid"
    end
  end

  test "email validation should reject invalid addresses" do
    invalid_addresses = %w[user@example,com user_at_foo.org user.name@example.
                           foo@bar_baz.com foo@bar+baz.com]
    invalid_addresses.each do | invalid_address |
      @user.email = invalid_address
      assert_not @user.valid?, "#{invalid_address.inspect} should be invalid"
    end
  end

  test "email addresses should be unique" do
    duplicate_user = @user.dup
    duplicate_user.email = @user.email.upcase
    @user.save
    assert_not duplicate_user.valid?
  end

  test "email addresses should be saved as lower-case" do
    mixed_case_email = "FoO@bAr.coM"
    @user.email = mixed_case_email
    @user.save
    assert_equal mixed_case_email.downcase, @user.reload.email
  end

  test "password should be present" do
    @user.password = @user.password_confirmation = " " * 8
    assert_not @user.valid?
  end

  test "email should have minimum length" do
    @user.password = @user.password_confirmation = "a1Aa!@k*"
    assert @user.valid?, "#{@user.password} should be valid"
  end

  test "password should contain at least one number" do
    @user.password = @user.password_confirmation = "foobarrr"
    assert_not @user.valid?, "#{@user.password} should be invalid"
  end

  test "should not be greater than 40 chars" do
    @user.password = @user.password_confirmation = "a1Da" * 10 + "a" # 41 chars
    assert_not @user.valid?, "#{@user.password} should not be valid"
  end
end

require 'test_helper'

class UsersSignupTest < ActionDispatch::IntegrationTest

  test "invalid signup information" do
    get signup_path
    assert_no_difference 'User.count' do
      post users_path, params: { user: { name:  "",
                                         email: "user@invalid",
                                         password:              "foo",
                                         password_confirmation: "bar" } }
    end

    assert_template 'users/new'
    assert_select 'div#error_explanation', 1
    assert_select 'div.alert-danger', 1
    assert_select 'div#error_explanation ul' do
        assert_select 'li', 5
    end
  end

  test "valid signup information" do
    get signup_path
    assert_difference 'User.count', 1 do
      post users_path, params: { user: { name:  "Example User",
                                         email: "user@example.com",
                                         password:              "Password1!",
                                         password_confirmation: "Password1!" } }
    end
    follow_redirect!
    assert_template 'users/show'
    assert_equal "Welcome to the Sample App!", flash[:success]
    assert is_logged_in?
  end
end

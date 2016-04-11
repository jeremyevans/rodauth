require File.expand_path("spec_helper", File.dirname(__FILE__))

describe 'Rodauth confirm password feature' do
  it "should support confirming passwords" do
    rodauth do
      enable :login, :change_login, :confirm_password, :password_grace_period
      change_login_requires_password? false
      before_change_login_route do
        unless password_recently_entered?
          session[:confirm_password_redirect] = request.path_info
          redirect '/confirm-password'
        end
      end
    end
    roda do |r|
      r.rodauth
      r.get("reset"){session[:last_password_entry] = Time.now.to_i - 400; "a"}
      view :content=>""
    end

    login

    visit '/change-login'
    page.title.must_equal 'Change Login'

    visit '/reset'
    page.body.must_equal 'a'

    visit '/change-login'
    page.title.must_equal 'Confirm Password'
    fill_in 'Password', :with=>'012345678'
    click_button 'Confirm Password'
    page.find('#error_flash').text.must_equal "There was an error confirming your password"
    page.html.must_include("invalid password")

    fill_in 'Password', :with=>'0123456789'
    click_button 'Confirm Password'
    page.find('#notice_flash').text.must_equal "Your password has been confirmed"

    fill_in 'Login', :with=>'foo3@example.com'
    fill_in 'Confirm Login', :with=>'foo3@example.com'
    click_button 'Change Login'
    page.find('#notice_flash').text.must_equal "Your login has been changed"
  end
end

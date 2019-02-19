require File.expand_path("spec_helper", File.dirname(__FILE__))
describe 'Rodauth login return to feature' do

  it "should remember requested url and return to it after login" do
    rodauth{enable :login_return_to}
    roda do |r|
      r.rodauth
      r.get "target" do
        rodauth.require_login
        view :content=>"Target Page"
      end
      r.root{view :content=>"Logged In"}
    end

    visit '/target'
    page.title.must_equal 'Login'
    fill_in 'Login', :with=>"foo@example.com"
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.current_path.must_equal '/target'
    page.find('#notice_flash').text.must_equal 'You have been logged in'
    page.html.must_include("Target Page")

  end
end

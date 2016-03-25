require File.expand_path("spec_helper", File.dirname(__FILE__))

describe 'Rodauth password complexity feature' do
  it "should do additional password complexity checks" do
    rodauth do
      enable :login, :change_password, :password_complexity
      change_password_requires_password? false
      password_dictionary_file 'spec/words'
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.current_path.must_equal '/'

    visit '/change-password'
    passwords = <<-END.split
      a1OX

      sdflksdfl
      sdflks!fl
      Sdflksdfl
      dfl1sdfl
      DFL1SDFL
      DFL!SDFL

      Aqwerty12
      Aazerty12
      HA123ha
      HA234ha
      HA345ha
      HA456ha
      HA567ha
      HA678ha
      HA789ha
      HA890ha

      Helll0

      password
      password1
      Password1
      1Password1
      1PaSSword1
      1P@$5w0Rd1
      2398|3@$+7809
      2|!7+1e
      l4$7$123
      N!88|e56
    END

    passwords.each do |pass|
      fill_in 'New Password', :with=>pass
      fill_in 'Confirm Password', :with=>pass
      click_button 'Change Password'
      page.html.must_include("invalid password")
      page.find('#error_flash').text.must_equal "There was an error changing your password"
    end

     fill_in 'New Password', :with=>'footpassword'
    fill_in 'Confirm Password', :with=>'footpassword'
    click_button 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"
  end

  it "should support default dictionary" do
    default_dictionary = '/usr/share/dict/words'
    skip("#{default_dictionary} not present") unless File.file?(default_dictionary)
    password = File.read(default_dictionary).split.sort_by{|w| w.length}.last

    rodauth do
      enable :login, :change_password, :password_complexity
      change_password_requires_password? false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.current_path.must_equal '/'

    visit '/change-password'
    fill_in 'New Password', :with=>"135#{pass}135"
    fill_in 'Confirm Password', :with=>"135#{pass}135"
    click_button 'Change Password'
    page.html.must_include("invalid password")
    page.find('#error_flash').text.must_equal "There was an error changing your password"

    fill_in 'New Password', :with=>'footpassword'
    fill_in 'Confirm Password', :with=>'footpassword'
    click_button 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"
  end

  it "should support no dictionary" do
    default_dictionary = '/usr/share/dict/words'
    skip("#{default_dictionary} not present") unless File.file?(default_dictionary)
    password = File.read(default_dictionary).split.sort_by{|w| w.length}.last

    rodauth do
      enable :login, :change_password, :password_complexity
      change_password_requires_password? false
      password_dictionary_file false
    end
    roda do |r|
      r.rodauth
      r.root{view :content=>""}
    end

    visit '/login'
    fill_in 'Login', :with=>'foo@example.com'
    fill_in 'Password', :with=>'0123456789'
    click_button 'Login'
    page.current_path.must_equal '/'

    visit '/change-password'
    fill_in 'New Password', :with=>"password123"
    fill_in 'Confirm Password', :with=>"password123"
    click_button 'Change Password'
    page.html.must_include("invalid password")
    page.find('#error_flash').text.must_equal "There was an error changing your password"

    fill_in 'New Password', :with=>'Password1'
    fill_in 'Confirm Password', :with=>'Password1'
    click_button 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"
  end
end

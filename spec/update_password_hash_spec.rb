require_relative 'spec_helper'

describe 'Rodauth update_password feature' do
  [false, true].each do |ph|
    it "should support updating passwords for accounts #{'with account_password_hash_column' if ph} if hash cost changes" do
      cost = BCrypt::Engine::MIN_COST
      rodauth do
        enable :login, :logout, :update_password_hash
        account_password_hash_column :ph if ph
        password_hash_cost{cost}
      end
      roda do |r|
        r.rodauth
        next unless rodauth.logged_in?
        rodauth.account_from_session
        r.root{rodauth.send(:get_password_hash)}
      end

      login
      content = page.html

      logout
      login
      page.current_path.must_equal '/'
      content.must_equal page.html

      cost += 1
      logout
      login
      new_content = page.html
      page.current_path.must_equal '/'
      content.wont_equal new_content

      logout
      login
      page.current_path.must_equal '/'
      new_content.must_equal page.html
    end

    it "should support updating passwords for accounts #{'with account_password_hash_column' if ph} if hash algorithm changes from bcrypt to argon2" do
      rodauth do
        enable :login, :logout, :update_password_hash, :argon2
        account_password_hash_column :ph if ph
        password_hash_algorithm 'argon2'
      end
      roda do |r|
        r.rodauth
        next unless rodauth.logged_in?
        rodauth.account_from_session
        r.root{rodauth.send(:get_password_hash)}
      end

      login
      content = page.html

      logout
      login
      page.current_path.must_equal '/'
      content.must_equal page.html
    end
  end

  [false, true].each do |ph|
    around(:all) do |&block|
      DB.transaction(:rollback=>:always) do
        hasher = ::Argon2::Password.new({ t_cost: 1, m_cost: 3 })
        hash = hasher.create('01234567')
        table = ENV['RODAUTH_SEPARATE_SCHEMA'] ? Sequel[:rodauth_test_password][:account_password_hashes] : :account_password_hashes
        DB[table].insert(:id=>DB[:accounts].insert(:email=>'foo2@example.com', :status_id=>2, :ph=>hash), :password_hash=>hash)
        super(&block)
      end
    end

    it "should support updating passwords for accounts #{'with account_password_hash_column' if ph} if hash cost changes via argon2" do
      cost = { t_cost: 1, m_cost: 3 }
      rodauth do
        enable :login, :logout, :update_password_hash, :argon2
        account_password_hash_column :ph if ph
        password_hash_cost{cost}
      end
      roda do |r|
        r.rodauth
        next unless rodauth.logged_in?
        rodauth.account_from_session
        r.root{rodauth.send(:get_password_hash)}
      end

      login(:login=>'foo2@example.com', :pass=>'01234567')
      content = page.html

      logout
      login(:login=>'foo2@example.com', :pass=>'01234567')
      page.current_path.must_equal '/'
      content.must_equal page.html

      cost = { t_cost: 2, m_cost: 3 }
      logout
      login(:login=>'foo2@example.com', :pass=>'01234567')
      new_content = page.html
      page.current_path.must_equal '/'
      content.wont_equal new_content

      logout
      login(:login=>'foo2@example.com', :pass=>'01234567')
      page.current_path.must_equal '/'
      new_content.must_equal page.html
    end

    it "should support updating passwords for accounts #{'with account_password_hash_column' if ph} if hash algorithm changes from argon2 to bcrypt" do
      rodauth do
        enable :login, :logout, :update_password_hash, :argon2
        account_password_hash_column :ph if ph
        password_hash_algorithm 'bcrypt'
      end
      roda do |r|
        r.rodauth
        next unless rodauth.logged_in?
        rodauth.account_from_session
        r.root{rodauth.send(:get_password_hash)}
      end

      login(:login=>'foo2@example.com', :pass=>'01234567')
      content = page.html

      logout
      login(:login=>'foo2@example.com', :pass=>'01234567')
      page.current_path.must_equal '/'
      content.must_equal page.html
    end
  end

  it "should handle case where the user does not have a password" do
    rodauth do
      enable :login, :logout, :update_password_hash, :change_password
      account_password_hash_column :ph
      require_password_confirmation? false
    end
    roda do |r|
      r.rodauth
      r.root{view(:content=>rodauth.logged_in? ? 'Logged In' : 'Not Logged')}
    end

    login
    DB[:accounts].update(:ph=>nil)
    visit '/change-password'
    fill_in 'New Password', :with=>'0123456789'
    click_button 'Change Password'
    page.find('#notice_flash').text.must_equal "Your password has been changed"

    login
    page.html.must_include 'Logged In'
  end
end

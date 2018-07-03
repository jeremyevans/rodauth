require File.expand_path("spec_helper", File.dirname(__FILE__))

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
  end
end

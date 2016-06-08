Dir.chdir('demo-site')
instance_eval(File.read('config.ru'), __FILE__)

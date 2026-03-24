# caxlsx and other gems emit Ruby 4.0 performance warnings about un-frozen string
# literals. These are gem-side issues — suppress them to keep output clean.
Warning[:performance] = false

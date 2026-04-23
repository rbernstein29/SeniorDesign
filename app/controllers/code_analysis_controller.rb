class CodeAnalysisController < ApplicationController
  before_action :require_admin

  MAX_FILE_SIZE = 1.megabyte

  def index
    @result   = nil
    @filename = nil
  end

  def analyze
    file = params[:source_file]
    return redirect_to code_analysis_path, alert: 'No file uploaded.' unless file.respond_to?(:read)
    return redirect_to code_analysis_path, alert: 'File too large (max 1 MB).' if file.size > MAX_FILE_SIZE

    content   = file.read.force_encoding('UTF-8').scrub
    @filename = file.original_filename
    ext       = File.extname(@filename).delete_prefix('.')

    @result = GeminiService.analyze_code(content, ext, @filename)
    render :index
  end
end

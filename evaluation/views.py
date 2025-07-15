from django.shortcuts import render, redirect
from django.views.decorators.http import require_http_methods


#임시 강의 더미 데이터 (나중엔 DB 연결 예정)
DUMMY_LECTURES = [
    {"id": 1, "code": "HBJQ001-1", "title": "정보보안", "professor": "교수1", "credit": 3, "feedback": None},
    {"id": 2, "code": "HBJQ002-1", "title": "네트워크", "professor": "교수2", "credit": 3, "feedback": "좋아요"},
    {"id": 3, "code": "HBJQ003-1", "title": "DB", "professor": "교수3", "credit": 3, "feedback": None},
]


DUMMY_LECTURES1 = [
    {"id": 1, "code": "HBJQ001-1", "title": "모바일프로그래밍", "professor": "교수1", "credit": 3, "feedback": None},
    {"id": 2, "code": "HBJQ002-1", "title": "네트워크", "professor": "교수2", "credit": 3, "feedback": "좋아요"},
    {"id": 3, "code": "HBJQ003-1", "title": "DB", "professor": "교수3", "credit": 3, "feedback": None},
]

def mid_evaluation(request):
    #나중엔 DB에서 filter(user=..., semester=...) 로 변경
    lectures = DUMMY_LECTURES
    return render(request, 'evaluation/mid_evaluation.html', {'lectures': lectures})


@require_http_methods(["GET", "POST"])
def mid_eval_form(request, lecture_id):
    #나중엔 Lecture.objects.get(id=lecture_id) 로 변경
    lecture = next((lec for lec in DUMMY_LECTURES if lec["id"] == lecture_id), None)

    if not lecture:
        return render(request, '404.html')

    if request.method == "POST":
        score = request.POST.get('score')
        comment = request.POST.get('comment')

        print(f"[DEBUG] 평가 저장 예정: {lecture['code']}, 평점={score}, 코멘트={comment}")

        #TODO: DB 저장 로직 자리
        return redirect('mid_evaluation')

    return render(request, 'evaluation/mid_eval_form.html', {'lecture': lecture})


def final_evaluation(request):
    #나중엔 DB에서 filter(user=..., semester=...) 로 변경
    lectures = DUMMY_LECTURES1
    return render(request, 'evaluation/final_evaluation.html', {'lectures': lectures})

@require_http_methods(["GET", "POST"])
def final_eval_form(request, lecture_id):
    #나중엔 Lecture.objects.get(id=lecture_id) 로 변경
    lecture = next((lec for lec in DUMMY_LECTURES1 if lec["id"] == lecture_id), None)

    if not lecture:
        return render(request, '404.html')

    if request.method == "POST":
        score = request.POST.get('score')
        comment = request.POST.get('comment')

        print(f"[DEBUG] 평가 저장 예정: {lecture['code']}, 평점={score}, 코멘트={comment}")

        #TODO: DB 저장 로직 자리
        return redirect('final_evaluation')

    return render(request, 'evaluation/final_eval_form.html', {'lecture': lecture})

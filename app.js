// Функция запуска салюта
function launchConfetti() {
  confetti({
    particleCount: 100,
    spread: 70,
    origin: { y: 0.6 }
  });
}

// Проверка, чётное ли число
function isEven(num) {
  return num % 2 === 0;
}

// Получение значений из полей
function getInputValues() {
  const num1 = parseFloat(document.getElementById('input1').value);
  const num2 = parseFloat(document.getElementById('input2').value);
  return { num1, num2 };
}

// Обновление результата и запуск салюта, если результат чётный
function updateResult(value) {
  document.getElementById('result').innerText = value;
  if (isEven(value)) {
    launchConfetti();
  }
}

// Генерация случайного числа в диапазоне
function getRandomNumber(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Операции
document.getElementById('plus').addEventListener('click', function() {
  const { num1, num2 } = getInputValues();
  const result = num1 + num2;
  updateResult(result);
});

document.getElementById('minus').addEventListener('click', function() {
  const { num1, num2 } = getInputValues();
  const result = num1 - num2;
  updateResult(result);
});

document.getElementById('multiply').addEventListener('click', function() {
  const { num1, num2 } = getInputValues();
  const result = num1 * num2;
  updateResult(result);
});

document.getElementById('divide').addEventListener('click', function() {
  const { num1, num2 } = getInputValues();
  if (num2 === 0) {
    document.getElementById('result').innerText = 'Деление на ноль!';
  } else {
    const result = num1 / num2;
    updateResult(result);
  }
});

document.getElementById('power').addEventListener('click', function() {
  const { num1, num2 } = getInputValues();
  const result = Math.pow(num1, num2);
  updateResult(result);
});

document.getElementById('sqrt').addEventListener('click', function() {
  const num1 = parseFloat(document.getElementById('input1').value);
  const result = Math.sqrt(num1);
  updateResult(result);
});

// Генерация случайного числа
document.getElementById('randomNumber').addEventListener('click', function() {
  const min = parseFloat(document.getElementById('min-value').value);
  const max = parseFloat(document.getElementById('max-value').value);

  if (!isNaN(min) && !isNaN(max) && min <= max) {
    const randomNumber = getRandomNumber(min, max);
    updateResult(randomNumber); // Отображаем случайное число в элементе "result"
  } else {
    document.getElementById('result').innerText = 'Ошибка диапазона!';
  }
});
